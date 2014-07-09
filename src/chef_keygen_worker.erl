%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92 -*-
%% ex: ts=4 sw=4 et
%% Copyright 2013 Chef Software, Inc. All Rights Reserved.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%
%% @doc chef_keygen_worker makes RSA key pairs just for you.
%%
%% chef_keygen_worker is a single-use worker gen_server. When started, it generates an RSA
%% key pair and stores it in server state. Calling {@link get_key_pair/1} will return the
%% generated key pair and terminate the worker.
%%
%% Instead of relying on NIFs and correct use of libopenssl, this code shells out to openssl
%% to generate a private key and then uses functions in the public_key module to extract and
%% encode the public key. The call to the openssl command line utility is done via open_port
%% and requires message passing. For this reason, the call is made inside init to avoid
%% issues from misuse of this single key pair worker.
%%
%% Basic use is:
%% ```
%% {ok, Pid} = chef_keygen_worker:start_link(),
%% #key_pair{public_key = Pub, private_key = Priv} = chef_keygen_worker:get_key_pair(Pid)
%% '''
%%
%% There are two app config keys you can use to control the behavior of this worker. The key
%% `keygen_size' determines the RSA key size in bits to generate. If not specified, the
%% default is 2048. For use with the Chef authentication protocol, you should not use a key
%% size less than 2048. Since key generation is a CPU intensive task, the operation is
%% carried out under a timeout configured via `keygen_timeout'. If a key generation takes
%% longer than this value (default is 1000 ms) then the atom `keygen_timeout' is returned
%% instead of a key. Both values are read from app config on each invocation.
%%
-module(chef_keygen_worker).

-behaviour(gen_server).

%% API
-export([
         get_key_pair/1,
         start_link/1
        ]).

%% gen_server callbacks
-export([
         code_change/3,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         init/1,
         terminate/2
        ]).

-include_lib("public_key/include/public_key.hrl").
-include("chef_authn.hrl").
-include("chef_keygen.hrl").

start_link(Config) ->
    gen_server:start_link(?MODULE, Config, []).

-spec get_key_pair(pid()) -> #key_pair{} | keygen_timeout.
get_key_pair(Pid) ->
    gen_server:call(Pid, get_key_pair).

init(block) ->
    {ok, generate_key_pair()};
init({send_to, Pid}) ->
    {ok, {send_to, Pid}, 0}.

handle_call(get_key_pair, _From, KeyPair) ->
    {stop, normal, KeyPair, sent};
handle_call(_Request, _From, State) ->
    {reply, ignored, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info(timeout, {send_to, Pid}) ->
    KeyPair = generate_key_pair(),
    Pid ! KeyPair,
    {stop, normal, sent};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

-spec generate_key_pair() -> #key_pair{} | keygen_timeout.
generate_key_pair() ->
    KeySize = envy:get(chef_authn, keygen_size, ?DEFAULT_KEY_SIZE, integer),
    PrivKey = genrsa(KeySize),
    case PrivKey of
        keygen_timeout ->
            keygen_timeout;
        {keygen_error, _} = Result->
            Result;
        _ ->
            PubKey = getpub(PrivKey),
            #key_pair{public_key = PubKey, private_key = PrivKey}
    end.

genrsa(Size) ->
    SSize = erlang:integer_to_list(Size),
    OpenSsl = chef_keygen_worker_sup:get_openssl(),
    Cmd = OpenSsl ++ " genrsa " ++ SSize ++ " 2>/dev/null",
    Port = erlang:open_port({spawn, Cmd}, [{line, 256}, eof, exit_status]),
    gather_data(Port).

getpub(Priv) ->
    #'RSAPrivateKey'{modulus = Modulus, publicExponent = PubExp} =
        chef_authn:extract_private_key(Priv),
    PubKey = #'RSAPublicKey'{modulus = Modulus, publicExponent = PubExp},
    PemEntry = public_key:pem_entry_encode('SubjectPublicKeyInfo', PubKey),
    public_key:pem_encode([PemEntry]).

gather_data(Port) ->
    Timeout = envy:get(chef_authn, keygen_timeout, ?DEFAULT_KEY_TIMEOUT, integer),
    Data = gather_data(Port, Timeout, []),
    maybe_gather_exit_status(Port, Timeout, Data).


%%
%% Read lines from the command until EOF.
%%
gather_data(Port, Timeout, Acc) ->
    %% Note exit_status may be sent while we are here, but we deliberately exclude it in the filter.
    %% Use care when modifying; a catchall term here will break things.
    receive
        {Port, eof} ->
            Data = maybe_strip_eol(Acc),
            erlang:iolist_to_binary(lists:reverse(Data));
        {Port, {data, {eol, Line}}} ->
            gather_data(Port, Timeout, ["\n", Line | Acc])
    after Timeout ->
            keygen_timeout
    end.

%% Remove trailing end of line. If the command fails, we get an empty return accumulator
maybe_strip_eol(["\n"|Data]) ->
    Data;
maybe_strip_eol(Data) ->
    Data.


%%
%% Exit status can arrive before or after the EOF from the command.
%%
%% From reading the erlang beam interpreter code, there is no process to defer the exit
%% status message until after the pipe from the command has drained. However, we use the
%% selective filtering of receive to ignore any exit status messages until after finishing
%% reading the pipe.
%%
maybe_gather_exit_status(_Port, _Timeout, keygen_timeout=Data) ->
    Data;
maybe_gather_exit_status(Port, Timeout, Data) ->
    receive
        {Port, {exit_status, 0}} ->
            Data;
        {Port, {exit_status, Status}} ->
            {keygen_error, Status}
    after Timeout ->
            keygen_timeout
    end.
