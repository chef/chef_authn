%% Copyright 2012 Opscode, Inc. All Rights Reserved.
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

-module(chef_keyring_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

-define(LINK, test_dir("reload_test.pem")).

test_dir(File) ->
    filename:join(test_dir(), File).

test_dir() ->
    filename:join(code:priv_dir(chef_authn), "../test").

private_key() ->
    content(test_dir("testkey.pem")).

webui_pub() ->
    content(test_dir("webui_pub.pem")).

content(Path) ->
    {ok, Key} = file:read_file(Path),
    Key.

unset_chef_authn_env() ->
    application:unset_env(chef_authn, keyring),
    application:unset_env(chef_authn, keyring_file),
    application:unset_env(chef_authn, secrets_module),
    application:unset_env(chef_authn, keyring_dir).

-define(assert_public_key(Key),
    ?assertMatch(#'RSAPublicKey'{}, Key),
    ?assert(Key#'RSAPublicKey'.modulus > 0)).

-define(assert_private_key(Key),
    ?assertMatch(#'RSAPrivateKey'{}, Key),
    ?assert(Key#'RSAPrivateKey'.prime1 > 0)).

lookup_test_() ->
    {foreach,
     fun() ->
             application:set_env(chef_authn, keyring,
                                 [{test1, test_dir("testkey.pem")}]),
             application:set_env(chef_authn, keyring_dir, test_dir()),
             error_logger:tty(false),
             chef_keyring:start_link()
     end,
     fun(_) -> cleanup end,
     [{"private key fetch",
       fun() ->
               {ok, Key} = chef_keyring:get_key(testkey),
               ?assert_private_key(Key)
       end},

      {"public key fetch",
       fun() ->
               {ok, Key} = chef_keyring:get_key(webui_pub),
               ?assert_public_key(Key)
       end},

      {"public key in certificate fetch",
       fun() ->
               {ok, Key} = chef_keyring:get_key(example_cert),
               ?assert_public_key(Key)
       end},

      {"fetching unknown key returns error tuple",
       fun() ->
               ?assertMatch({error, unknown_key},
                            chef_keyring:get_key('no-such-key'))
       end},

      {"list_keys returns all the keys",
       fun() ->
               Keys = lists:sort(chef_keyring:list_keys()),
               ?assertEqual(['clownco-org-admin', example_cert,
                             knife_ruby_187_priv, knife_ruby_187_pub,
                             knife_ruby_192_priv, knife_ruby_192_pub,
                             other_cert, platform_public_key_example,
                             'skynet-org-admin', spki_public,
                             test1, testkey, webui_pub],
                            Keys)
       end}
     ]}.


load_file_test_() ->
    {setup,
     fun() ->
             unset_chef_authn_env(),
             error_logger:tty(false),
             chef_keyring:start_link()
     end,
     fun(_) -> ok
     end,
     [
      {"Test basic key file reading",
       fun() ->
               {ok, Key1} = chef_keyring:get_key('clownco-org-admin'),
               {ok, Key2} = chef_keyring:get_key('testkey'),
               ?assert_private_key(Key1),
               ?assert_private_key(Key2)
       end},
      {"Test key file reloading",
       fun() ->
               application:set_env(chef_authn, keyring,
                                   [{test1, test_dir("testkey.pem")}]),
               {ok, Key1} = chef_keyring:get_key(test1),
               ?assert_private_key(Key1),

               application:set_env(chef_authn, keyring,
                                   [{test1, test_dir("webui_pub.pem")}]),
               chef_keyring:reload(),

               {ok, Key2} = chef_keyring:get_key(test1),
               ?assert_public_key(Key2)
       end}
     ]
    }.

load_secrets_module_test_() ->
    {setup,
     fun() ->
             unset_chef_authn_env(),
             application:set_env(chef_authn, secrets_module,
                                 {chef_secrets, get,
                                  [{pivotal, [<<"chef-server">>, <<"superuser_key">>]},
                                   {webui_pub, [<<"chef-server">>, <<"webui_pub_key">>]}]}),
             error_logger:tty(false),
             meck:new(chef_secrets, [non_strict]),
             meck:expect(chef_secrets, get,
                         fun(<<"chef-server">>, <<"superuser_key">>) -> {ok, private_key()};
                            (<<"chef-server">>, <<"webui_pub_key">>) -> {ok, private_key()}
                         end),
             chef_keyring:start_link(),
             chef_keyring:reload()
     end,
     fun(_) ->
             meck:unload(chef_secrets),
             unset_chef_authn_env()

     end,
     [
      {"Test basic secrets_module secrets getting",
       fun() ->
               {ok, Key0} = chef_keyring:get_key(pivotal),
               {ok, Key1} = chef_keyring:get_key(webui_pub),
               ?assert_private_key(Key0),
               ?assert_private_key(Key1)
       end}
     ]
    }.

load_dir_test_() ->
    {setup,
     fun() ->
             unset_chef_authn_env(),
             application:set_env(chef_authn, keyring_dir, test_dir()),
             error_logger:tty(false),
             chef_keyring:start_link(),
             chef_keyring:reload()
     end,
     fun(_) -> ok
     end,
     [
      {"Test basic key dir reading",
       fun() ->
               {ok, Key1} = chef_keyring:get_key(testkey),
               ?assert_private_key(Key1)
       end}
     ]
    }.

reload_changed_dir_test_() ->
    {setup,
     fun() ->
             unset_chef_authn_env(),
             application:set_env(chef_authn, keyring_dir, test_dir()),
             file:delete(?LINK),
             error_logger:tty(false),
             chef_keyring:start_link(),
             chef_keyring:reload()
     end,
     fun(_) ->
             file:delete(?LINK)
     end,
     [
      {"Test basic reloading of dir when adding file",
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
               file:make_symlink(test_dir("testkey.pem"), ?LINK),
               timer:sleep(1000), %% I'm ashamed, but directory times are second resolution
               chef_keyring:reload_if_changed(),
               Stats3 = chef_keyring:stats(),
               ?assertNotEqual(Stats1, Stats3),

               {Result3, _} = chef_keyring:get_key('reload_test'),
               ?assertEqual(ok, Result3)
       end}
     ]
    }.

reload_changed_dir2_test_() ->
    {setup,
     fun() ->
             unset_chef_authn_env(),
             application:set_env(chef_authn, keyring,
                                 [{test1, test_dir("testkey.pem")}]),
             file:delete(?LINK),
             error_logger:tty(false),
             chef_keyring:start_link(),
             chef_keyring:reload()
     end,
     fun(_) ->
             file:delete(?LINK)
     end,
     [
      {"Test basic reloading when no dir",
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
    }.
