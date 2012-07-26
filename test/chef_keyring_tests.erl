-module(chef_keyring_tests).

-include_lib("eunit/include/eunit.hrl").

-define(SETUP, fun() ->
                       application:set_env(chef_common, keyring,
                                           [{test1, "../test/testkey.pem"}]),
                       application:set_env(chef_common, keyring_dir, "../test"),
                       chef_keyring:start_link() end).

lookup_test_() ->
    {foreach, ?SETUP,
     [{"Test private key fetch ",
       fun() ->
               {ok, Key} = chef_keyring:get_key(testkey),
               ?assertEqual(11, size(Key)),
               Key1 = tuple_to_list(Key),
               ['RSAPrivateKey', 'two-prime', FirstInt|_] = Key1,
               ?assert(is_integer(FirstInt))
       end},
      {"Test public key fetch",
       fun() ->
               {ok, Key} = chef_keyring:get_key(webui_pub),
               ?assertEqual(3, size(Key)),
               {'RSAPublicKey', KeyVal, Modulus} = Key,
               ?assert(is_integer(KeyVal)),
               ?assert(is_integer(Modulus))
       end},
      fun() ->
              ?assertMatch({error, unknown_key},
                           chef_keyring:get_key('no-such-key'))
      end,
      fun() ->
              Keys = lists:sort(chef_keyring:list_keys()),
              ?assertMatch(['clownco-org-admin', example_cert,
                            knife_ruby_187_priv, knife_ruby_187_pub,
                            knife_ruby_192_priv, knife_ruby_192_pub,
                            other_cert, platform_public_key_example,
                            'skynet-org-admin', spki_public,
                            test1, testkey, webui_pub],
                           Keys)
      end
     ]}.


load_file_test_() ->
    {setup,
     fun() ->
             application:unset_env(chef_common, keyring),
             application:unset_env(chef_common, keyring_dir),
             chef_keyring:start_link(),
             {ok}
     end,
     fun(_) -> ok
     end,
     fun({ok}) ->
             [
              {"Test basic key file reading",
               fun() ->
                       {ok, Key1} = chef_keyring:get_key('clownco-org-admin'),
                       ?assertEqual(element(1,Key1), 'RSAPrivateKey'),
                       {ok, Key2} = chef_keyring:get_key('testkey'),
                       ?assertEqual(element(1,Key2), 'RSAPrivateKey')
               end},
              {"Test key file reloading",
               fun() ->
                       application:set_env(chef_common, keyring,
                                           [{test1, "../test/testkey.pem"}]),

                       application:set_env(chef_common, keyring,
                                           [{test1, "../test/testkey.pem"}]),
                       {ok, Key1} = chef_keyring:get_key(test1),
                       ?assertEqual(element(1,Key1), 'RSAPrivateKey'),

                       application:set_env(chef_common, keyring,
                                           [{test1, "../test/webui_pub.pem"}]),

                       chef_keyring:reload(),

                       {ok, Key2} = chef_keyring:get_key(test1),
                       ?assertEqual(element(1,Key2), 'RSAPublicKey')
               end}
             ]
     end
    }.

load_dir_test_() ->
    {setup,
     fun() ->
             application:unset_env(chef_common, keyring),
             application:unset_env(chef_common, keyring_file),
             application:set_env(chef_common, keyring_dir, "../test"),
             chef_keyring:start_link(),
             chef_keyring:reload(),
             {ok}
     end,
     fun(_) -> ok
     end,
     fun({ok}) ->
             [
              {"Test basic key dir reading",
               fun() ->
                       {ok, Key1} = chef_keyring:get_key(testkey),
                       ?assertEqual(element(1,Key1), 'RSAPrivateKey')
               end}
             ]
     end
    }.

-define(LINK, "../test/reload_test.pem").

reload_changed_dir_test_() ->
    {setup,
     fun() ->
             application:unset_env(chef_common, keyring),
             application:unset_env(chef_common, keyring_file),
             application:set_env(chef_common, keyring_dir, "../test"),
             file:delete(?LINK),
             chef_keyring:start_link(),
             chef_keyring:reload(),
             {ok}
     end,
     fun(_) ->
             file:delete(?LINK)
     end,
     fun({ok}) ->
             [
              {"Test basic reloading of dir when adding file: " ?LINK,
               fun() ->
                       %% Check that key is unknown in initial state
                       Stats1 = chef_keyring:stats(),
                       Result1 = chef_keyring:get_key('reload_test'),
                       ?assertEqual({error, unknown_key}, Result1),

                       %% Trigger a reload and verify nothing has changed
                       timer:sleep(1000), %% I'm ashamed, but directory times are second resolution
                       chef_keyring:reload_if_changed(),
                       Stats2 = chef_keyring:stats(),
                       ?assertEqual(Stats1, Stats2),

                       Result2 = chef_keyring:get_key('reload_test'),
                       ?assertEqual({error, unknown_key}, Result2),

                       %% Add a new key, trigger a reload, and verify things have changed.
                       file:make_symlink("../test/testkey.pem", ?LINK),
                       timer:sleep(1000), %% I'm ashamed, but directory times are second resolution
                       chef_keyring:reload_if_changed(),
                       Stats3 = chef_keyring:stats(),
                       ?assert(Stats1 =/= Stats3),

                       {Result3, _} = chef_keyring:get_key('reload_test'),
                       ?assertEqual(Result3, 'ok')
               end}
             ]
     end
    }.

reload_changed_dir2_test_() ->
    {setup,
     fun() ->
             application:unset_env(chef_common, keyring),
             application:unset_env(chef_common, keyring_file),
             application:unset_env(chef_common, keyring_dir),
             application:set_env(chef_common, keyring,
                                 [{test1, "../test/testkey.pem"}]),
             file:delete(?LINK),
             chef_keyring:start_link(),
             chef_keyring:reload(),
             {ok}
     end,
     fun(_) ->
             file:delete(?LINK)
     end,
     fun({ok}) ->
             [
              {"Test basic reloading when no dir: " ?LINK,
               fun() ->
                       %% Check that key is unknown in initial state
                       Stats1 = chef_keyring:stats(),

                       %% Trigger a reload and verify nothing has changed
                       timer:sleep(1000), %% I'm ashamed, but directory times are second resolution
                       chef_keyring:reload_if_changed(),
                       Stats2 = chef_keyring:stats(),
                       ?assertEqual(Stats1, Stats2)
               end}
             ]
     end
    }.
