%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92 -*-
%% ex: ts=4 sw=4 et
%% Copyright 2013 Opscode, Inc. All Rights Reserved.
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
%% @doc supervisor for chef_keygen_worker throw-away key generator processs
%%
%% Example:
%% ```
%% chef_keygen_worker_sup:start_link().
%% {ok, Pid} = chef_keygen_worker_sup:new_worker(),
%% chef_keygen_worker:get_key_pair(Pid).
%% '''
%%
%% The app config key openssl_path allows the default command to be overridden
%%
-module(chef_keygen_worker_sup).

-include_lib("kernel/include/file.hrl").
-include("chef_keygen.hrl").
-behaviour(supervisor).

-export([
         init/1,
         new_worker/0,
         new_worker/1,
         start_link/0,
         get_openssl/0
        ]).

-define(EXEC_FLAGS, 8#111).

new_worker() ->
    new_worker(block).

new_worker(block) ->
    supervisor:start_child(?MODULE, [block]);
new_worker(Pid) when is_pid(Pid) ->
    supervisor:start_child(?MODULE, [{send_to, Pid}]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    _ = get_openssl(),
    Worker = {chef_keygen_worker, {chef_keygen_worker, start_link, []},
              temporary, brutal_kill, worker, [chef_keygen_worker]},
    Specs = [Worker],
    Restart = {simple_one_for_one, 1, 1},
    {ok, {Restart, Specs}}.

get_openssl() ->
    Default = os:find_executable(?OPENSSL_CMD),
    case envy:get(chef_authn, openssl_path, Default, string) of
        false ->
            erlang:error({missing_executable, ?OPENSSL_CMD});
        File ->
            case file:read_file_info(File) of
                {error, _Reason} ->
                    erlang:error({missing_executable, File});
                %% Check if file has execute flags set.
                {ok, #file_info{mode=Mode}} when (Mode band ?EXEC_FLAGS) =/= 0 ->
                    File;
                _X ->
                    io:fwrite("~p~n", [_X]),
                    erlang:error({bad_executable, File})
            end
    end.
