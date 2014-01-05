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
%% <li>keygen_timeout: Time allowed for the external key generation command (openssl). A
%% timeout atom is returned if the command takes longer than `Timeout' milliseconds. </li>
%% <li>keygen_cache_workers: The number of workers available to generate key pairs. This
%% should never be larger than the number of logical CPUs. Defaults to larger of 1 and half
%% the number of logical processors as reported by `erlang:system_info(logical_processors)'
%% </li>
%% <li>keygen_cache_pause: Time in milliseconds to use as throttle on key
%% generation. Workers will not be spawned more frequently than every `Pause'
%% milliseconds. If `Pause' is 0, there is no throttling. Since the cache will need to
%% refill on service restart, this is useful to tradeoff speed of cache fill for available
%% CPU to handle requests.</li>
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
-include("chef_keygen.hrl").

-define(SERVER, ?MODULE).


-record(state, {keys = [],
                max = ?DEFAULT_CACHE_SIZE,
                pause = ?DEFAULT_KEYGEN_PAUSE,
                avail_workers = 1,
                inflight = [],
                last_refill,
                timer
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
-spec get_key_pair() -> {PublicKey :: binary(), PrivateKey :: binary() } | keygen_timeout.
get_key_pair() ->
    Timeout = envy:get(chef_authn, keygen_timeout, ?DEFAULT_KEY_TIMEOUT, integer),
    case call_with_timeout(get_key_pair, Timeout) of
        cache_empty ->
            error_logger:warning_report({chef_keygen_cache, empty}),
            %% do inline keygen in the calling process to avoid blocking the server.
            export_key_pair(make_key_pair());
        #key_pair{} = KeyPair ->
            export_key_pair(KeyPair);
        timeout ->
            error_logger:warning_report({chef_keygen_cache, gen_server_timeout}),
            keygen_timeout
    end.

call_with_timeout(Msg, Timeout) ->
    try
        gen_server:call(?SERVER, Msg, Timeout)
    catch
        exit:{timeout, {gen_server, call, _}} ->
            timeout
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
    {ok, async_refill(State)}.

process_config(State) ->
    Max = envy:get(chef_authn, keygen_cache_size, ?DEFAULT_CACHE_SIZE, integer),
    Pause = envy:get(chef_authn, keygen_cache_pause, ?DEFAULT_KEYGEN_PAUSE, integer),
    Workers = envy:get(chef_authn, keygen_cache_workers, default_worker_count(), integer),
    error_logger:info_msg("chef_keygen_cache configured size:~p pause:~p avail_workers:~p", [Max, Pause, Workers]),
    State#state{max = Max, pause = Pause, avail_workers = Workers}.

%% If not configured, default to allowing up to half of available cores to be used for
%% keygen workers.
default_worker_count() ->
    %% docs say this can return 'unknown', but dialyzer complains.
    Cores = erlang:system_info(logical_processors),
    erlang:max(Cores div 2, 1).

handle_call(get_key_pair, _From, #state{keys = [KeyPair|Rest]} = State) ->
    State1 = State#state{keys = Rest},
    {reply, KeyPair, async_refill(State1)};
handle_call(get_key_pair, _From, #state{keys = []} = State) ->
    {reply, cache_empty, async_refill(State)};
handle_call(update_config, _From, State) ->
    NewState = process_config(State),
    {reply, ok, NewState};
handle_call(status, _From, State) ->
    #state{keys = Keys, max = Max, pause = Pause,
           avail_workers = Avail, inflight = Inflight} = State,
    Ans = [{keys, length(Keys)}, {max, Max}, {pause, Pause},
           {inflight, Inflight}, {avail_workers, Avail}],
    {reply, Ans, State};
handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
handle_call(kill_workers_for_test, _From, #state{inflight = Inflight} = State) ->
    [ erlang:exit(P, kill) || P <- Inflight ],
    {reply, {killed, Inflight}, State};
handle_call(_Request, _From, State) ->
    {reply, ignored, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info(keygen_timeout, #state{pause = Pause} = State) ->
    error_logger:warning_report({chef_keygen_cache, keygen_timeout}),
    {noreply, async_refill(State), Pause};
handle_info(#key_pair{} = KeyPair,
            #state{keys = Keys,
                   max = Max} = State) when length(Keys) < Max ->
    %% with the guard, we ignore key addition messages if we're full
    %% updating avail_workers handled by receiving 'DOWN' from monitor
    error_logger:info_report({chef_keygen_cache, received_key}),
    NewKeys = [KeyPair | Keys],
    NewState = State#state{keys = NewKeys},
    {noreply, async_refill(NewState)};
handle_info(timeout, State) ->
    {noreply, async_refill(State)};
handle_info({'DOWN', _MRef, process, Pid, Reason},
            #state{avail_workers = Avail, inflight = Inflight} = State) ->
    {RemovedCount, NewInflight} = lists:foldl(
                                    fun(ThePid, {0, Acc}) when ThePid =:= Pid ->
                                            log_non_normal(Pid, Reason),
                                            {1, Acc};
                                       (APid, {X, Acc}) ->
                                            {X, [APid | Acc]}
                                    end, {0, []}, Inflight),
    {noreply, State#state{avail_workers = Avail + RemovedCount, inflight = NewInflight}};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


async_refill(State) ->
    State1 = schedule_timeout(State),
    case should_run(State1) of
        true ->
            async_refill_in(State1);
        false ->
            State1
    end.

async_refill_in(#state{avail_workers = 0} = State) ->
    State;
async_refill_in(#state{keys = Keys, max = Max} = State) when length(Keys) == Max ->
    State;
async_refill_in(#state{avail_workers = N,
                       keys = Keys, max = Max,
                       inflight = Inflight} = State) ->
    Self = self(),
    NumKeysWanted = Max - length(Keys),
    WorkerSeq = lists:seq(1, erlang:min(N, NumKeysWanted)),
    %% Note that we'll get a DOWN message if we monitor a dead pid, so we don't have to
    %% worry about what happens between the supervisor starting the worker and our call to
    %% attach the monitor.
    Workers = [ chef_keygen_worker_sup:new_worker(Self) || _I <- WorkerSeq ],
    NewInflight = [
                   begin
                       _MRef = erlang:monitor(process, Pid),
                       Pid
                   end
                   || {ok, Pid} <- Workers ],
    OKCount = length(NewInflight),
    State#state{avail_workers = N - OKCount,
                inflight = NewInflight ++ Inflight,
                last_refill = os:timestamp()}.

schedule_timeout(#state{pause = Pause, timer = undefined} = State) ->
    TRef = erlang:send_after(Pause, self(), timeout),
    State#state{timer = TRef};
schedule_timeout(#state{pause = Pause, timer = Timer} = State) ->
    case erlang:read_timer(Timer) of
        false ->
            TRef = erlang:send_after(Pause, self(), timeout),
            State#state{timer = TRef};
        _ ->
            State
    end.

make_key_pair() ->
    {ok, Pid} = chef_keygen_worker_sup:new_worker(block),
    chef_keygen_worker:get_key_pair(Pid).

export_key_pair(#key_pair{public_key = Pub, private_key = Priv}) ->
    {Pub, Priv};
export_key_pair(keygen_timeout) ->
    keygen_timeout.

log_non_normal(_Pid, normal) ->
    ok;
log_non_normal(Pid, Reason) ->
    error_logger:error_report({chef_keygen_cache, worker_crash, Pid, Reason}).

%% Don't spawn works more frequently than Pause ms.
should_run(#state{last_refill = undefined}) ->
    true;
should_run(#state{pause = 0}) ->
    true;
should_run(#state{last_refill = LastRefill, pause = Pause}) ->
    PauseMicros = Pause * 1000,
    Now = os:timestamp(),
    timer:now_diff(Now, LastRefill) > PauseMicros.

