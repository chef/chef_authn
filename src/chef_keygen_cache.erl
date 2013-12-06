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
%% @doc chef_keygen_cache Precreates RSA key pairs and servers them when you ask.
%%
%% chef_keygen_cache is a gen_server that keeps a configurable number of RSA key pairs on
%% hand for fast delivery. There is a throttled mechanism (to avoid hogging CPU) to
%% replinish the key cache when it drops below the desired size. Keys are created on demand
%% if the cache is empty. If inline key generation exceeds a configured timeout, the atom
%% `timeout' is returned. Inline key generation happens in the calling process and does not
%% block the server.
%%
%% You can control the behavior of the key cache using the following app config keys:
%% <ul>
%% <li>keygen_size: Size in bits of the RSA keys to generate. Defaults to 2048. Mostly used
%% to speed up testing.</li>
%% <li>keygen_cache_size: The number of keys to store in the cache</li>
%% <li>keygen_cache_pause: Time in milliseconds to use as the gen_server timeout (idle
%% server timeout) used to throttle key generation. Keys will be added to the cache at a
%% rate less than or equal one key per `Pause' milliseconds</li>
%% <li>keygen_timeout: Time allowed for the external key generation command (openssl). A
%% timeout atom is returned if the command takes longer than `Timeout' milliseconds. </li>
%% </ul>

-module(chef_keygen_cache).

-behaviour(gen_server).

%% API
-export([
         get_key_pair/0,
         start_link/0,
         status/0,
         stop/0,
         update_config/0
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

-define(SERVER, ?MODULE).

-define(DEFAULT_CACHE_SIZE, 10).

%% milliseconds to pause between key generation calls when filling the cache. We use
%% gen_server's timeout mechanism so this really represents the length of time to pause when
%% the server is idle. This is appropriate because if clients are making key requests and
%% we're not full, there's little benefit to blocking the server to fill it rather than
%% simply serving those requests with inline keygen.
-define(DEFAULT_KEYGEN_PAUSE, 200).

-record(state, {keys = [],
                max = ?DEFAULT_CACHE_SIZE,
                pause = ?DEFAULT_KEYGEN_PAUSE
               }).

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

stop() ->
    gen_server:call(?SERVER, stop).

%% @doc Retrieve an RSA key pair from the cache.
%%
%% The return value is a tuple of the form `{PublicKey, PrivateKey}' where each element is a
%% binary containing the PEM encoded key. If no keys are available in the cache, a key will
%% be generated inline with this call. If key generation exceeds the timeout value specified
%% in app config `{chef_authn, kegen_timeout, Timeout}', then the atom `timeout' is
%% returned. Note that inline key generation, if needed, occurs in the process calling this
%% function, not in the server.
%%
-spec get_key_pair() -> {PublicKey :: binary(), PrivateKey :: binary() } | timeout.
get_key_pair() ->
    case gen_server:call(?SERVER, get_key_pair) of
        cache_empty ->
            error_logger:warning_report({chef_keygen_cache, empty}),
            %% do inline keygen in the calling process to avoid blocking the server.
            export_key_pair(make_key_pair());
        #key_pair{} = KeyPair ->
            export_key_pair(KeyPair)
    end.

%% @doc Return a proplist of status information about the state of the key cache.
-spec status() -> [{atom(), _}].
status() ->
    gen_server:call(?SERVER, status).

%% @doc Instruct the cache to reread app config values. This can be used if you want to
%% modify the cache size or cache pause values in a running cache.
-spec update_config() -> ok.
update_config() ->
    gen_server:call(?SERVER, update_config).

init([]) ->
    State = process_config(#state{keys = []}),
    {ok, State, State#state.pause}.

process_config(State) ->
    Max = envy:get(chef_authn, keygen_cache_size, ?DEFAULT_CACHE_SIZE, integer),
    Pause = envy:get(chef_authn, keygen_cache_pause, ?DEFAULT_KEYGEN_PAUSE, integer),
    error_logger:info_msg("chef_keygen_cache configured size:~p pause:~p", [Max, Pause]),
    State#state{max = Max, pause = Pause}.
    
handle_call(get_key_pair, _From, #state{pause = Pause, keys = [KeyPair|Rest]} = State) ->
    {reply, KeyPair, State#state{keys = Rest}, Pause};
handle_call(get_key_pair, _From, #state{keys = [], pause = Pause} = State) ->
    {reply, cache_empty, State, Pause};
handle_call(update_config, _From, State) ->
    NewState = process_config(State),
    {reply, ok, NewState, NewState#state.pause};
handle_call(status, _From, #state{keys = Keys, max = Max, pause = Pause} = State) ->
    Ans = [{keys, length(Keys)}, {max, Max}, {pause, Pause}],
    {reply, Ans, State, Pause};
handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
handle_call(_Request, _From, #state{pause = Pause} = State) ->
    {reply, ignored, State, Pause}.

handle_cast(_Request, #state{pause = Pause} = State) ->
    {noreply, State, Pause}.

handle_info(timeout, #state{keys = Keys,
                            max = Max,
                            pause = Pause} = State) when length(Keys) < Max ->
    KeyPair = make_key_pair(),
    NewKeys = case KeyPair of
                  timeout ->
                      error_logger:warning_report({chef_keygen_cache, keygen_timeout}),
                      Keys;
                  _ ->
                      [KeyPair | Keys ]
              end,
    case length(NewKeys) == Max of
        true ->
            error_logger:info_report({chef_keygen_cache, full});
        false ->
            ok
    end,
    {noreply, State#state{keys = NewKeys}, Pause};
handle_info(timeout, State) ->
    %% length of Keys >= Max. Nothing to do and no need to set the timeout.
    {noreply, State};
handle_info(_Info, #state{pause = Pause} = State) ->
    {noreply, State, Pause}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

make_key_pair() ->
    {ok, Pid} = chef_keygen_worker_sup:new_worker(),
    chef_keygen_worker:get_key_pair(Pid).

export_key_pair(#key_pair{public_key = Pub, private_key = Priv}) ->
    {Pub, Priv};
export_key_pair(timeout) ->
    timeout.

