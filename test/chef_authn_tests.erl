%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92 -*-
%% ex: ts=4 sw=4 et
%% @author Seth Falcon <seth@opscode.com>
%% @author Christopher Brown <cb@opscode.com>
%% @copyright 2011 Opscode, Inc.
%% @doc chef_authn - Request signing and authentication for Opscode Chef
%%
%% This module is an Erlang port of the mixlib-authentication Ruby gem.
%% It can be used to sign HTTP requests to send to a Chef server or to
%% validate such requests (for server implementation).

-module(chef_authn_tests).

-compile([export_all]).

-include("chef_authn.hrl").
-include_lib("eunit/include/eunit.hrl").



-define(path, <<"/organizations/clownco">>).
-define(path_with_query, <<"/organizations/clownco?a=1&b=2">>).
-define(hashed_path, <<"YtBWDn1blGGuFIuKksdwXzHU9oE=">>).

-define(body, <<"Spec Body">>).
-define(hashed_body, <<"DFteJZPVv6WKdQmMqZUQUumUyRs=">>).
-define(request_time_http, <<"Thu, 01 Jan 2009 12:00:00 GMT">>).
-define(request_time_erlang, {{2009, 1, 1}, {12, 0, 0}}).
-define(request_time_iso8601, <<"2009-01-01T12:00:00Z">>).
-define(user, <<"spec-user">>).

-define(X_OPS_AUTHORIZATION_LINES_V1_0,
        [
         <<"jVHrNniWzpbez/eGWjFnO6lINRIuKOg40ZTIQudcFe47Z9e/HvrszfVXlKG4">>,
         <<"NMzYZgyooSvU85qkIUmKuCqgG2AIlvYa2Q/2ctrMhoaHhLOCWWoqYNMaEqPc">>,
         <<"3tKHE+CfvP+WuPdWk4jv4wpIkAz6ZLxToxcGhXmZbXpk56YTmqgBW2cbbw4O">>,
         <<"IWPZDHSiPcw//AYNgW1CCDptt+UFuaFYbtqZegcBd2n/jzcWODA7zL4KWEUy">>,
         <<"9q4rlh/+1tBReg60QdsmDRsw/cdO1GZrKtuCwbuD4+nbRdVBKv72rqHX9cu0">>,
         <<"utju9jzczCyB+sSAQWrxSsXB/b8vV2qs0l4VD2ML+w==">>
        ]).

-define(X_OPS_AUTHORIZATION_LINES,
        [
         <<"UfZD9dRz6rFu6LbP5Mo1oNHcWYxpNIcUfFCffJS1FQa0GtfU/vkt3/O5HuCM">>,
         <<"1wIFl/U0f5faH9EWpXWY5NwKR031Myxcabw4t4ZLO69CIh/3qx1XnjcZvt2w">>,
         <<"c2R9bx/43IWA/r8w8Q6decuu0f6ZlNheJeJhaYPI8piX/aH+uHBH8zTACZu8">>,
         <<"vMnl5MF3/OIlsZc8cemq6eKYstp8a8KYq9OmkB5IXIX6qVMJHA6fRvQEB/7j">>,
         <<"281Q7oI/O+lE8AmVyBbwruPb7Mp6s4839eYiOdjbDwFjYtbS3XgAjrHlaD7W">>,
         <<"FDlbAG7H8Dmvo+wBxmtNkszhzbBnEYtuwQqT8nM/8A==">>
        ]).

-define(X_OPS_CONTENT_HASH, <<"DFteJZPVv6WKdQmMqZUQUumUyRs=">>).

-define(expected_sign_string_v10,
        iolist_to_binary(io_lib:format(
                           "Method:~s\nHashed Path:~s\n"
                           "X-Ops-Content-Hash:~s\n"
                           "X-Ops-Timestamp:~s\n"
                           "X-Ops-UserId:~s",
                           ["POST", ?hashed_path, ?hashed_body,
                            ?request_time_iso8601, ?user]))).

-define(expected_sign_string,
        iolist_to_binary(io_lib:format(
                           "Method:~s\nHashed Path:~s\n"
                           "X-Ops-Content-Hash:~s\n"
                           "X-Ops-Timestamp:~s\n"
                           "X-Ops-UserId:~s",
                           ["POST", ?hashed_path, ?hashed_body,
                            ?request_time_iso8601, chef_authn:hash_string(?user)]))).

hashed_path_test() ->
    ?assertEqual(?hashed_path, chef_authn:hash_string(chef_authn:canonical_path(?path))).

hashed_path_query_params_are_ignored_test() ->
    %% for X-Ops_sign: version=1.0, query params are not included in
    %% the hash of the path for request verification.
    ?assertEqual(?hashed_path, chef_authn:hash_string(chef_authn:canonical_path(?path_with_query))).

hashed_body_test() ->
    ?assertEqual(?hashed_body, chef_authn:hashed_body(?body)).

canonical_time_test() ->
    % This date format comes from Ruby's default printing,
    % but doesn't correspond to the HTTP rfc2616 format
    % Time = "Thu Jan 01 12:00:00 -0000 2009",
    ?assertEqual(?request_time_iso8601, chef_authn:canonical_time(?request_time_http)).

canonicalize_request_v1_0_test() ->
    Val1 = chef_authn:canonicalize_request(?hashed_body, ?user, <<"post">>, ?request_time_iso8601, ?path, ?signing_algorithm, ?signing_version_v1_0),
    ?assertEqual(?expected_sign_string_v10, Val1),

    % verify normalization
    Val2 = chef_authn:canonicalize_request(?hashed_body, ?user, <<"post">>, ?request_time_iso8601,
                                <<"/organizations//clownco/">>, ?signing_algorithm, ?signing_version_v1_0),
    ?assertEqual(?expected_sign_string_v10, Val2).

canonicalize_request_test() ->
    Val1 = chef_authn:canonicalize_request(?hashed_body, ?user, <<"post">>, ?request_time_iso8601, ?path, ?signing_algorithm, ?signing_version_v1_1),
    ?assertEqual(?expected_sign_string, Val1),

    % verify normalization
    Val2 = chef_authn:canonicalize_request(?hashed_body, ?user, <<"post">>, ?request_time_iso8601,
                                <<"/organizations//clownco/">>, ?signing_algorithm, ?signing_version_v1_1),
    ?assertEqual(?expected_sign_string, Val2).

sign_request_1_0_test() ->
    {ok, RawKey} = file:read_file("../test/private_key"),
    Private_key = chef_authn:extract_private_key(RawKey),
    AuthLine = fun(I) -> lists:nth(I, ?X_OPS_AUTHORIZATION_LINES_V1_0) end,
    EXPECTED_SIGN_RESULT =
        [
         {<<"X-Ops-Content-Hash">>, ?X_OPS_CONTENT_HASH},
         {<<"X-Ops-UserId">>, ?user},
         {<<"X-Ops-Sign">>, <<"version=1.0">>},
         {<<"X-Ops-Timestamp">>, ?request_time_iso8601},
         {<<"X-Ops-Authorization-1">>, AuthLine(1)},
         {<<"X-Ops-Authorization-2">>, AuthLine(2)},
         {<<"X-Ops-Authorization-3">>, AuthLine(3)},
         {<<"X-Ops-Authorization-4">>, AuthLine(4)},
         {<<"X-Ops-Authorization-5">>, AuthLine(5)},
         {<<"X-Ops-Authorization-6">>, AuthLine(6)}
        ],
    Sig = chef_authn:sign_request(Private_key, ?body, ?user, <<"post">>,
                       ?request_time_erlang, ?path, ?signing_algorithm, ?signing_version_v1_0),
    ?assertEqual(EXPECTED_SIGN_RESULT, Sig).

sign_request_1_1_test() ->
    {ok, RawKey} = file:read_file("../test/private_key"),
    Private_key = chef_authn:extract_private_key(RawKey),
    AuthLine = fun(I) -> lists:nth(I, ?X_OPS_AUTHORIZATION_LINES) end,
    EXPECTED_SIGN_RESULT =
        [
         {<<"X-Ops-Content-Hash">>, ?X_OPS_CONTENT_HASH},
         {<<"X-Ops-UserId">>, ?user},
         {<<"X-Ops-Sign">>, <<"version=1.1">>},
         {<<"X-Ops-Timestamp">>, ?request_time_iso8601},
         {<<"X-Ops-Authorization-1">>, AuthLine(1)},
         {<<"X-Ops-Authorization-2">>, AuthLine(2)},
         {<<"X-Ops-Authorization-3">>, AuthLine(3)},
         {<<"X-Ops-Authorization-4">>, AuthLine(4)},
         {<<"X-Ops-Authorization-5">>, AuthLine(5)},
         {<<"X-Ops-Authorization-6">>, AuthLine(6)}
        ],
    Sig = chef_authn:sign_request(Private_key, ?body, ?user, <<"post">>,
                       ?request_time_erlang, ?path, ?signing_algorithm, ?signing_version_v1_1),
    ?assertEqual(EXPECTED_SIGN_RESULT, Sig).

decrypt_sig_test() ->
    AuthSig = iolist_to_binary(?X_OPS_AUTHORIZATION_LINES),
    {ok, Public_key} = file:read_file("../test/example_cert.pem"),
    ?assertEqual(?expected_sign_string,
                 chef_authn:decrypt_sig(AuthSig, {cert, Public_key})).

decrypt_sig_fail_platform_style_test() ->
    AuthSig = iolist_to_binary(?X_OPS_AUTHORIZATION_LINES),
    {ok, Bin} = file:read_file("../test/platform_public_key_example.pem"),
    ?assertEqual(decrypt_failed, chef_authn:decrypt_sig(AuthSig, {key, Bin})).

decrypt_sig_fail_spki_test() ->
    AuthSig = iolist_to_binary(?X_OPS_AUTHORIZATION_LINES),
    {ok, Bin} = file:read_file("../test/spki_public.pem"),
    ?assertEqual(decrypt_failed, chef_authn:decrypt_sig(AuthSig, {key, Bin})).

time_in_bounds_test() ->
    T1 = {{2011,1,26},{2,3,0}},

    % test seconds
    T2 = {{2011,1,26},{2,3,4}},
    ?assertEqual(false, chef_authn:time_in_bounds(T1, T2, 2)),
    ?assertEqual(true, chef_authn:time_in_bounds(T1, T2, 5)),

    % test minutes
    T3 = {{2011,1,26},{2,6,0}},
    ?assertEqual(false, chef_authn:time_in_bounds(T1, T3, 60*2)),
    ?assertEqual(true, chef_authn:time_in_bounds(T1, T3, 60*5)),

    % test hours
    T4 = {{2011,1,26},{4,0,0}},
    ?assertEqual(false, chef_authn:time_in_bounds(T1, T4, 60*60)),
    ?assertEqual(true, chef_authn:time_in_bounds(T1, T4, 60*60*3)).

make_skew_time() ->
    % force time skew to allow for now
    ReqTimeEpoch = calendar:datetime_to_gregorian_seconds(
                     chef_authn:time_iso8601_to_date_time(?request_time_iso8601)),
    NowEpoch = calendar:datetime_to_gregorian_seconds(
                 calendar:now_to_universal_time(os:timestamp())),
    (NowEpoch - ReqTimeEpoch) + 100.

authenticate_user_request_test_() ->
    {ok, RawKey} = file:read_file("../test/private_key"),
    Private_key = chef_authn:extract_private_key(RawKey),
    {ok, Public_key0} = file:read_file("../test/example_cert.pem"),
    Public_key = {cert, Public_key0},
    Headers = chef_authn:sign_request(Private_key, ?body, ?user, <<"post">>,
                           ?request_time_erlang, ?path),
    GetHeader = fun(X) -> proplists:get_value(X, Headers) end,
    % force time skew to allow a request to be processed 'now'
    TimeSkew = make_skew_time(),

    [
     {"authenticated user request",
      fun() ->
              Ok = chef_authn:authenticate_user_request(GetHeader, <<"post">>, ?path, ?body,
                                             Public_key, TimeSkew),
              ?assertEqual({name, ?user}, Ok)
      end
     },

     {"no_authn: bad path",
      fun() ->
              BadPath = chef_authn:authenticate_user_request(GetHeader, <<"post">>,
                                                  <<"/organizations/foo">>,
                                                  ?body, Public_key, TimeSkew),
              ?assertEqual({no_authn, bad_sig}, BadPath)
      end
     },

     {"no_authn: bad method",
      fun() ->
              BadMethod = chef_authn:authenticate_user_request(GetHeader, <<"PUT">>, ?path,
                                                    ?body, Public_key, TimeSkew),
              ?assertEqual({no_authn, bad_sig}, BadMethod)
      end
     },

     {"no_authn: bad body",
      fun() ->
              BadBody = chef_authn:authenticate_user_request(GetHeader, <<"post">>, ?path,
                                                  <<"xyz">>, Public_key, TimeSkew),
              ?assertEqual({no_authn, bad_sig}, BadBody)
      end
     },

     {"no_authn: bad time",
      fun() ->
              BadTime = chef_authn:authenticate_user_request(GetHeader, <<"post">>, ?path,
                                                  ?body, Public_key, 600),
              ?assertEqual({no_authn, bad_clock}, BadTime)
      end
      },

     {"no_authn: bad key",
      fun() ->
              {ok, Other_key} = file:read_file("../test/other_cert.pem"),
              BadKey = chef_authn:authenticate_user_request(GetHeader, <<"post">>, ?path,
                                                 ?body, {cert, Other_key},
                                                 TimeSkew),
              ?assertEqual({no_authn, bad_sig}, BadKey)
      end
      },

     {"no_authn: missing timestamp header",
      fun() ->
              Headers2 = proplists:delete(<<"X-Ops-Timestamp">>, Headers),
              GetHeader2 = fun(X) -> proplists:get_value(X, Headers2) end,
              ?assertEqual({no_authn, {missing_headers, [<<"X-Ops-Timestamp">>]}},
                           chef_authn:authenticate_user_request(GetHeader2, <<"post">>, ?path,
                                                     ?body, Public_key, TimeSkew))
      end
     },

     {"no_authn: missing user header",
      fun() ->
              Headers2 = proplists:delete(<<"X-Ops-UserId">>, Headers),
              GetHeader2 = fun(X) -> proplists:get_value(X, Headers2) end,
              ?assertEqual({no_authn, {missing_headers, [<<"X-Ops-UserId">>]}},
                           chef_authn:authenticate_user_request(GetHeader2, <<"post">>, ?path,
                                                     ?body, Public_key, TimeSkew))
      end
     },

     {"no_authn: missing all authorization-i headers",
      fun() ->
              Headers2 = lists:filter(
                           fun({<<"X-Ops-Authorization-", _/binary>>, _}) -> false;
                              (_Else) -> true
                           end, Headers),
              GetHeader2 = fun(X) -> proplists:get_value(X, Headers2) end,
              ?assertEqual({no_authn, bad_sig},
                           chef_authn:authenticate_user_request(GetHeader2, <<"post">>, ?path,
                                                     ?body, Public_key, TimeSkew))
      end
     },

     {"no_authn: missing one authorization-i header",
      fun() ->
              Headers2 = lists:filter(
                           fun({<<"X-Ops-Authorization-5", _/binary>>, _}) -> false;
                              (_Else) -> true
                           end, Headers),
              GetHeader2 = fun(X) -> proplists:get_value(X, Headers2) end,
              ?assertEqual({no_authn, bad_sig},
                           chef_authn:authenticate_user_request(GetHeader2, <<"post">>, ?path,
                                                     ?body, Public_key, TimeSkew))
      end
     },

     {"no_authn: mismatched signing description",
      fun() ->
              Headers2 = lists:keyreplace(<<"X-Ops-Sign">>, 1, Headers,
                                          {<<"X-Ops-Sign">>, <<"version=2.0">>}),
              GetHeader2 = fun(X) -> proplists:get_value(X, Headers2) end,
              ?assertEqual({no_authn, bad_sign_desc},
                           chef_authn:authenticate_user_request(GetHeader2, <<"post">>, ?path,
                                                     ?body, Public_key, TimeSkew))
      end
     },

     {"no_authn: missing signing description",
      fun() ->
              Headers2 = lists:keydelete(<<"X-Ops-Sign">>, 1, Headers),
              GetHeader2 = fun(X) -> proplists:get_value(X, Headers2) end,
              ?assertEqual({no_authn, {missing_headers, [<<"X-Ops-Sign">>]}},
                            chef_authn:authenticate_user_request(GetHeader2, <<"post">>, ?path,
                                                      ?body, Public_key, TimeSkew))
      end
     }
     ].

validate_headers_test_() ->
    {ok, RawKey} = file:read_file("../test/private_key"),
    Private_key = chef_authn:extract_private_key(RawKey),
    Headers = chef_authn:sign_request(Private_key, ?body, ?user, <<"post">>,
                           calendar:universal_time(), ?path),
    GetHeader = fun(X) -> proplists:get_value(X, Headers) end,
    MissingOneTests =
        [ fun() ->
                  Headers2 = proplists:delete(H, Headers),
                  GetHeader2 = fun(X) -> proplists:get_value(X, Headers2) end,
                  ?assertThrow({missing_headers, [H]}, chef_authn:validate_headers(GetHeader2, 10))
          end || H <- ?required_headers ],
    [{algorithm, _SignAlgorithm}, {version, SignVersion}] = chef_authn:validate_headers(GetHeader, 10),
    [?_assertEqual(lists:member(SignVersion, ?signing_versions), true),
     ?_assertThrow({missing_headers, ?required_headers},
                   chef_authn:validate_headers(fun(<<_X/binary>>) -> undefined end, 1)) ]
        ++ MissingOneTests.

parse_signing_description_1_0_test_() ->
    Cases = [{<<"version=1.0">>, [{<<"version">>, <<"1.0">>}]},
             {undefined, []},
             {<<"a=1;b=2">>, [{<<"a">>, <<"1">>}, {<<"b">>, <<"2">>}]}],
    [ ?_assertEqual(Want, chef_authn:parse_signing_description(In))
      || {In, Want} <- Cases ].

parse_signing_description_1_1_test_() ->
    Cases = [{<<"version=1.1">>, [{<<"version">>, <<"1.1">>}]},
             {undefined, []},
             {<<"a=1;b=2">>, [{<<"a">>, <<"1">>}, {<<"b">>, <<"2">>}]}],
    [ ?_assertEqual(Want, chef_authn:parse_signing_description(In))
      || {In, Want} <- Cases ].

decode_cert_test() ->
    {ok, Bin} = file:read_file("../test/example_cert.pem"),
    Cert = chef_authn:decode_cert(Bin),
    ?assertEqual('RSAPublicKey', erlang:element(1, Cert)).

decode_public_key_platform_test() ->
    %% platform-style key
    {ok, Bin} = file:read_file("../test/platform_public_key_example.pem"),
    PubKey = chef_authn:decode_public_key(Bin),
    Coded = public_key:encrypt_public(<<"open sesame">>, PubKey),
    ?assertEqual(true, is_binary(Coded)).

decode_public_key_spki_test() ->
    %% platform-style key
    {ok, Bin} = file:read_file("../test/spki_public.pem"),
    %% verify valid key, by encrypting something, will error if
    %% key is bad.
    PubKey = chef_authn:decode_public_key(Bin),
    Coded = public_key:encrypt_public(<<"open sesame">>, PubKey),
    ?assertEqual(true, is_binary(Coded)).

