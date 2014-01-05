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

-module(chef_keygen_cache_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

start_keygen_cache(KeySize, CacheSize, Pause, GenTimeout) ->
    application:set_env(chef_authn, keygen_size, KeySize),
    application:set_env(chef_authn, keygen_cache_size, CacheSize),
    application:set_env(chef_authn, keygen_cache_pause, Pause),
    application:set_env(chef_authn, keygen_timeout, GenTimeout),
    ensure_worker_sup(),
    {ok, CachePid} = chef_keygen_cache:start_link(),
    CachePid.

ensure_worker_sup() ->            
    case erlang:whereis(chef_keygen_worker_sup) of
        undefined ->
            chef_keygen_worker_sup:start_link();
        _ ->
            ok
    end.

cleanup_cache(_) ->
    chef_keygen_cache:stop(),
    ok.

get_key_pair_happy_path_1024_test_() ->
    {setup,
     fun() ->
             start_keygen_cache(1024, 2, 100, 1000)
     end,
     fun cleanup_cache/1,
     fun() ->
             %% FIXME: allow cache to fill
             timer:sleep(1000),
             {Pub, Priv} = chef_keygen_cache:get_key_pair(),
             ?assertMatch(#'RSAPrivateKey'{}, chef_authn:extract_private_key(Priv)),
             ?assertMatch(#'RSAPublicKey'{}, chef_authn:extract_public_key(Pub)),
             ?assertEqual(1024, key_size(Pub))
     end}.

get_key_pair_happy_path_2048_test_() ->
    {setup,
     fun() ->
             start_keygen_cache(2048, 1, 100, 2000)
     end,
     fun cleanup_cache/1,
     fun() ->
             %% FIXME: allow cache to fill
             timer:sleep(1000),
             {Pub, Priv} = chef_keygen_cache:get_key_pair(),
             ?assertMatch(#'RSAPrivateKey'{}, chef_authn:extract_private_key(Priv)),
             ?assertMatch(#'RSAPublicKey'{}, chef_authn:extract_public_key(Pub)),
             ?assertEqual(2048, key_size(Pub))
     end}.

get_key_pair_timeout_test_() ->
    {setup,
     fun() ->
             start_keygen_cache(2048, 2, 100, 50)
     end,
     fun cleanup_cache/1,
     fun() ->
             Got = chef_keygen_cache:get_key_pair(),
             ?assertEqual(keygen_timeout, Got)
     end}.

get_key_pair_from_empty_cache_test_() ->
    {setup,
     fun() ->
             start_keygen_cache(1024, 0, 10000, 500)
     end,
     fun cleanup_cache/1,
     fun() ->
             Keys = [ chef_keygen_cache:get_key_pair() || _I <- [1, 2, 3] ],
             %% remove any timeout values
             ?assertEqual([keygen_timeout, keygen_timeout, keygen_timeout], Keys)
     end}.

cache_fills_and_replenishes_test_() ->
    {setup,
     fun() ->
             start_keygen_cache(1024, 3, 50, 500)
     end,
     fun cleanup_cache/1,
     fun() ->
             ?assertEqual(3, poll_cache_stat(keys, 3, 60, 10)),
             %% exhaust keys
             [ chef_keygen_cache:get_key_pair() || _I <- [1, 2, 3] ],
             application:set_env(chef_authn, keygen_cache_size, 4),
             chef_keygen_cache:update_config(),
             %% verify replenish
             ?assertEqual(4, poll_cache_stat(keys, 4, 60, 10))
     end}.

cache_handles_worker_crashes_test_() ->
    {setup,
     fun() ->
             start_keygen_cache(2048, 10, 50, 1000)
     end,
     fun cleanup_cache/1,
     fun() ->
             %% give time for the cache to load, grab a key
             timer:sleep(1000),
             chef_keygen_cache:get_key_pair(),
             {killed, KilledWorkers} = gen_server:call(chef_keygen_cache, kill_workers_for_test),
             %% purpose of this test is to verify recovery
             ?assert(length(KilledWorkers) > 0),
             %% workers have been killed, give the cache some time to recover
             timer:sleep(1000),
             ?assertEqual(10, poll_cache_stat(keys, 10, 60, 10))
     end}.

cache_handles_gen_server_timeout_test_() ->
    {setup,
     fun() ->
             start_keygen_cache(1024, 1, 50, 1000)
     end,
     fun cleanup_cache/1,
     fun() ->
             application:set_env(chef_authn, keygen_timeout, 0),
             ?assertEqual(keygen_timeout, chef_keygen_cache:get_key_pair())
     end}.

key_size(Pub) ->
    PK = chef_authn:extract_public_key(Pub),
    M = PK#'RSAPublicKey'.modulus,
    Bytes = erlang:size(erlang:term_to_binary(M)),
    %% basically we only are dealing with 1024 or 2048 key sizes for
    %% now.
    case Bytes bsr 7 of
        1 ->
            1024;
        2 ->
            2048
    end.

poll_cache_stat(_Key, _Expect, _Delay, 0) ->
    erlang:error({poll_cache_state, reached_max_retries});
poll_cache_stat(Key, Expect, Delay, N) ->
    Stats = chef_keygen_cache:status(),
    case proplists:get_value(Key, Stats) of
        Expect ->
            Expect;
        _ ->
            timer:sleep(Delay),
            poll_cache_stat(Key, Expect, Delay, N - 1)
    end.

%% [X] cache empty
%% [X] see some timeout values
%% [ ] cache replenishes.
%% [ ] cache size config works
%% [ ] cache pause works
%% [ ] key size is respected
