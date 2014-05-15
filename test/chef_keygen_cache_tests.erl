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

start_keygen_cache(KeySize, CacheSize, GenTimeout) ->
    application:set_env(chef_authn, keygen_size, KeySize),
    application:set_env(chef_authn, keygen_cache_size, CacheSize),
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
    application:unset_env(chef_authn, keygen_start_size),
    application:unset_env(chef_authn, keygen_size),
    application:unset_env(chef_authn, keygen_cache_size),
    application:unset_env(chef_authn, keygen_timeout),
    ok.

get_key_pair_happy_path_1024_test_() ->
    {setup,
     fun() ->
             application:set_env(chef_authn, keygen_start_size, 1),
             start_keygen_cache(1024, 2, 1000)
     end,
     fun cleanup_cache/1,
     fun() ->
             {Pub, Priv} = chef_keygen_cache:get_key_pair(),
             ?assertMatch(#'RSAPrivateKey'{}, chef_authn:extract_private_key(Priv)),
             ?assertMatch(#'RSAPublicKey'{}, chef_authn:extract_public_key(Pub)),
             ?assertEqual(1024, key_size(Pub))
     end}.

get_key_pair_happy_path_2048_test_() ->
    {setup,
     fun() ->
             application:set_env(chef_authn, keygen_start_size, 1),
             start_keygen_cache(2048, 1, 2000)
     end,
     fun cleanup_cache/1,
     fun() ->
             {Pub, Priv} = chef_keygen_cache:get_key_pair(),
             ?assertMatch(#'RSAPrivateKey'{}, chef_authn:extract_private_key(Priv)),
             ?assertMatch(#'RSAPublicKey'{}, chef_authn:extract_public_key(Pub)),
             ?assertEqual(2048, key_size(Pub))
     end}.

get_key_pair_timeout_test_() ->
    {setup,
     fun() ->
             start_keygen_cache(2048, 2, 50)
     end,
     fun cleanup_cache/1,
     fun() ->
             Got = chef_keygen_cache:get_key_pair(),
             ?assertEqual(keygen_timeout, Got)
     end}.

get_key_pair_from_empty_cache_test_() ->
    {setup,
     fun() ->
             start_keygen_cache(1024, 0, 500)
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
             application:set_env(chef_authn, keygen_start_size, 3),
             start_keygen_cache(1024, 3, 500)
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

cache_handles_gen_server_timeout_test_() ->
    {setup,
     fun() ->
             start_keygen_cache(1024, 1, 1000)
     end,
     fun cleanup_cache/1,
     fun() ->
             application:set_env(chef_authn, keygen_timeout, 0),
             ?assertEqual(keygen_timeout, chef_keygen_cache:get_key_pair())
     end}.

cache_disallows_invalid_config_test_() ->
    NoLink = fun() ->
                     gen_server:start({local, chef_keygen_cache}, chef_keygen_cache, [], [])
             end,
    {setup,
     fun() ->
             ok
     end,
     fun(_) ->
             application:unset_env(chef_authn, keygen_start_size),
             ok
     end,
     [{"negative start size",
       fun() ->
               application:set_env(chef_authn, keygen_start_size, -3),
               Result = NoLink(),
               ?assertMatch({error, {_Reason, _Trace}}, Result),
               {error, {Reason, _}} = Result,
               ?assertMatch({invalid_config, {chef_authn, [{keygen_start_size,-3},
                                                           {keygen_cache_size,10}]}}, Reason)
       end},
      {"start size too large",
       fun() ->
               application:set_env(chef_authn, keygen_start_size, 30),
               Result = NoLink(),
               ?assertMatch({error, {_Reason, _Trace}}, Result),
               {error, {Reason, _}} = Result,
               ?assertMatch({invalid_config, {chef_authn, [{keygen_start_size,30},
                                                           {keygen_cache_size,10}]}}, Reason)
       end}
     ]}.

%% Tests guarded by SLOW_TESTS take a bit longer to run and rely on
%% timing of key generation. They may require tuning depending on the
%% machine on which they are run. However, they provide coverage that
%% is useful to exercise during development.
-ifdef(SLOW_TESTS).

cache_handles_worker_crashes_test_() ->
    {setup,
     fun() ->
             start_keygen_cache(2048, 10, 1000)
     end,
     fun cleanup_cache/1,
     fun() ->
             {killed, KilledWorkers} = gen_server:call(chef_keygen_cache, kill_workers_for_test),
             %% purpose of this test is to verify recovery
             ?assert(length(KilledWorkers) > 0),
             %% workers have been killed, give the cache some time to recover
             timer:sleep(2000),
             ?assertEqual(10, poll_cache_stat(keys, 10, 60, 10))
     end}.

cache_handles_worker_crashes_with_one_worker_test_() ->
    {setup,
     fun() ->
             application:set_env(chef_authn, keygen_cache_workers, 1),
             start_keygen_cache(2048, 3, 1000),
             {killed, KilledWorkers} = gen_server:call(chef_keygen_cache, kill_workers_for_test),
             ?assert(length(KilledWorkers) == 1),
             ok
     end,
     fun cleanup_cache/1,
     fun() ->
             timer:sleep(3000),
             ?assertEqual(3, poll_cache_stat(keys, 3, 60, 10))
     end}.

cache_handles_worker_timeouts_on_start_test_() ->
    {setup,
     fun() ->
             application:set_env(chef_authn, keygen_start_size, 10),
             start_keygen_cache(2048, 10, 500),
             ok
     end,
     fun cleanup_cache/1,
     fun() ->
             ?assertEqual(10, poll_cache_stat(keys, 10, 60, 10))
     end}.

cache_handles_worker_timeouts_while_running_test_() ->
    {setup,
     fun() ->
             application:set_env(chef_authn, keygen_start_size, 0),
             start_keygen_cache(2048, 10, 500),
             ok
     end,
     fun cleanup_cache/1,
     fun() ->
             ?assertEqual(10, poll_cache_stat(keys, 10, 600, 100))
     end}.

-endif.

key_size(Pub) ->
    PK = chef_authn:extract_public_key(Pub),
    M = PK#'RSAPublicKey'.modulus,
    bit_size(binary:encode_unsigned(M)).

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
