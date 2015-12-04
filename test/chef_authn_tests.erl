%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92 -*-
%% ex: ts=4 sw=4 et
%% @author Seth Falcon <seth@opscode.com>
%% @author Christopher Brown <cb@opscode.com>
%% @doc Tests for chef_authn - Request signing and authentication for Opscode Chef


-module(chef_authn_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").
-include("../src/chef_authn.hrl").

-define(path, <<"/organizations/clownco">>).
-define(path_with_query, <<"/organizations/clownco?a=1&b=2">>).
-define(hashed_path_sha1, <<"YtBWDn1blGGuFIuKksdwXzHU9oE=">>).
-define(hashed_path_sha256, <<"Z3EsTMw/UBNY9n+q+WBWTJmeVg8hQFbdFzVWRxW4dOA=">>).

-define(body, <<"Spec Body">>).
-define(hashed_body_sha1, <<"DFteJZPVv6WKdQmMqZUQUumUyRs=">>).
-define(hashed_body_sha256, <<"hDlKNZhIhgso3Fs0S0pZwJ0xyBWtR1RBaeHs1DrzOho=">>).
-define(request_time_http, <<"Thu, 01 Jan 2009 12:00:00 GMT">>).
-define(request_time_iso8601, "2009-01-01T12:00:00Z").
-define(request_time_erlang, {{2009, 1, 1}, {12, 0, 0}}).
-define(user, <<"spec-user">>).

-define(PRIVATE_KEYS, "clownco-org-admin.pem", "skynet-org-admin.pem", "testkey.pem"]).

-define(KEYFILES, [ "example_cert.pem", "other_cert.pem", "platform_public_key_example.pem",
                    "spki_public.pem", "webui_pub.pem" ]).


-define(X_OPS_USERID, "spec-user").

-define(X_OPS_AUTHORIZATION_LINES_V1_0,
        [
         "jVHrNniWzpbez/eGWjFnO6lINRIuKOg40ZTIQudcFe47Z9e/HvrszfVXlKG4",
         "NMzYZgyooSvU85qkIUmKuCqgG2AIlvYa2Q/2ctrMhoaHhLOCWWoqYNMaEqPc",
         "3tKHE+CfvP+WuPdWk4jv4wpIkAz6ZLxToxcGhXmZbXpk56YTmqgBW2cbbw4O",
         "IWPZDHSiPcw//AYNgW1CCDptt+UFuaFYbtqZegcBd2n/jzcWODA7zL4KWEUy",
         "9q4rlh/+1tBReg60QdsmDRsw/cdO1GZrKtuCwbuD4+nbRdVBKv72rqHX9cu0",
         "utju9jzczCyB+sSAQWrxSsXB/b8vV2qs0l4VD2ML+w=="
        ]).

-define(X_OPS_AUTHORIZATION_LINES_V1_1,
        [
         "UfZD9dRz6rFu6LbP5Mo1oNHcWYxpNIcUfFCffJS1FQa0GtfU/vkt3/O5HuCM",
         "1wIFl/U0f5faH9EWpXWY5NwKR031Myxcabw4t4ZLO69CIh/3qx1XnjcZvt2w",
         "c2R9bx/43IWA/r8w8Q6decuu0f6ZlNheJeJhaYPI8piX/aH+uHBH8zTACZu8",
         "vMnl5MF3/OIlsZc8cemq6eKYstp8a8KYq9OmkB5IXIX6qVMJHA6fRvQEB/7j",
         "281Q7oI/O+lE8AmVyBbwruPb7Mp6s4839eYiOdjbDwFjYtbS3XgAjrHlaD7W",
         "FDlbAG7H8Dmvo+wBxmtNkszhzbBnEYtuwQqT8nM/8A=="
        ]).
-define(X_OPS_AUTHORIZATION_LINES_V1_2,
        [
          "HtjhPysvmPf7mFHZ+Ze4rLMucDv4ImPxv5kdJghpVwLo9tuE6VSmbuh3tIBp",
          "OmVH1sKOqyv6x5fkLaHq0FIYTEgcdXrN86rkFJBvExRzOuL7JHGXKIIzohc9",
          "BZBcF2LAGv2UY33TMXLhQYIIKh/5uWYZ7QsHjadgWo5nEiFpiy5VCoMKidmr",
          "DH7jYUZeXCFMgfsLlN6mlilc/iAGnktJwhAQPvIDgJS1cOHqFeWzaU2FRjvQ",
          "h6AUrsvhJ6C/5uJu6h0DT4uk5w5uVameyI/Cs+0KI/XLCk27dOl4X+SqBN9D",
          "FDp0m8rzMtOdsPkO/IAgbdpHTWoh8AXmPhh8t6+PfQ=="
        ]).

-define(X_OPS_AUTHORIZATION_LINES_V1_3_SHA1,
        [
         "Dh7xqnM3HabvuPVTsJCvHSWGyipvv0xkF9u7XfomC0tDHBF8wG4kEToRI7/1",
         "CSa97jlHLQ+VqNq76uy2mxg0PBxPLxPcz+VREJxnxEv+gEEr6MAeMpV97ip0",
         "VICuUZ3hPIVNl9hIjmaeOnQSbtJZZOIik0g0O+bpd7AQKa/Y7r2jw42D/Kgg",
         "L/ts6ntD2wKb92iPZ5bEXYIJFKVKb7j10PTcHLxkMWd64Cd7GZAdHHl4z8/t",
         "VZ5XCe23960z08d2P2I+iYBBCxRCOPwafBvbt0ubls2vecraHQYYXMXovjmV",
         "Rxh8xRaTfEhpWwZJa1ONVvsldZlvGiHO/jhmRJ9oCA=="
        ]).

-define(X_OPS_AUTHORIZATION_LINES_V1_3_SHA256,
        [
         "BjR+iTK2eOgwmT2yGqLvE7Fp+VlpRGyL1dVoF2DmhUPO7EVsnxx2s32AmlOw",
         "EpaACpav8SoB7K4rpOo3gfBm0XAYLnLLWzcec2OQG2O0wxxHiKVn4qWEe7Cs",
         "RZ903DGM54t4uK75vx6wwoEdZqZe21npsLK+F3oAqnkgp+YXmlYv9Se5tFKB",
         "0GWM1ibGJMjUIFAm7vxzjcuEvkkKN49MnXeMAAykfymcs74RU6xEKYzzSAyC",
         "ygkV6xQSapDMp/aY29cVA/1FgZeVMhnFSTjtqBehchZYwXswr0A72A86gID9",
         "h2QsUpmQJwbOK3bb1GptAnd5IiLzIxtu+vFeY6h4eA=="
        ]
       ).

-define(X_OPS_CONTENT_HASH, "DFteJZPVv6WKdQmMqZUQUumUyRs=").
-define(X_OPS_CONTENT_HASH_SHA256, "hDlKNZhIhgso3Fs0S0pZwJ0xyBWtR1RBaeHs1DrzOho=").

-define(expected_sign_string_v10,
        iolist_to_binary(io_lib:format(
                           "Method:~s\nHashed Path:~s\n"
                           "X-Ops-Content-Hash:~s\n"
                           "X-Ops-Timestamp:~s\n"
                           "X-Ops-UserId:~s",
                           ["POST", ?hashed_path_sha1, ?hashed_body_sha1,
                            ?request_time_iso8601, ?user]))).

-define(expected_sign_string_v11,
        iolist_to_binary(io_lib:format(
                           "Method:~s\nHashed Path:~s\n"
                           "X-Ops-Content-Hash:~s\n"
                           "X-Ops-Timestamp:~s\n"
                           "X-Ops-UserId:~s",
                           ["POST", ?hashed_path_sha1, ?hashed_body_sha1,
                            ?request_time_iso8601, chef_authn:hash_string(?user)]))).

-define(expected_sign_string_v12,
        iolist_to_binary(io_lib:format(
                           "Method:~s\nHashed Path:~s\n"
                           "X-Ops-Content-Hash:~s\n"
                           "X-Ops-Timestamp:~s\n"
                           "X-Ops-UserId:~s",
                           ["POST", ?hashed_path_sha1, ?hashed_body_sha1,
                            ?request_time_iso8601, chef_authn:hash_string(?user)]))).

-define(expected_sign_string_v13_sha1,
        iolist_to_binary(io_lib:format(
                           "Method:~s\nHashed Path:~s\n"
                           "X-Ops-Content-Hash:~s\n"
                           "X-Ops-Sign:algorithm=~s;version=~s\n"
                           "X-Ops-Timestamp:~s\n"
                           "X-Ops-UserId:~s\n"
                           "X-Ops-Server-API-Version:~B",
                           ["POST", ?hashed_path_sha1, ?hashed_body_sha1,
                            ?SIGNING_ALGORITHM_SHA1, ?SIGNING_VERSION_V1_3,
                            ?request_time_iso8601,
                            chef_authn:hash_string(?user,
                                                   {?SIGNING_ALGORITHM_SHA1,
                                                    ?SIGNING_VERSION_V1_3}),
                            1
                           ]))).

-define(expected_sign_string_v13_sha1_api_default,
        iolist_to_binary(io_lib:format(
                           "Method:~s\nHashed Path:~s\n"
                           "X-Ops-Content-Hash:~s\n"
                           "X-Ops-Sign:algorithm=~s;version=~s\n"
                           "X-Ops-Timestamp:~s\n"
                           "X-Ops-UserId:~s\n"
                           "X-Ops-Server-API-Version:~B",
                           ["POST", ?hashed_path_sha1, ?hashed_body_sha1,
                            ?SIGNING_ALGORITHM_SHA1, ?SIGNING_VERSION_V1_3,
                            ?request_time_iso8601,
                            chef_authn:hash_string(?user,
                                                   {?SIGNING_ALGORITHM_SHA1,
                                                    ?SIGNING_VERSION_V1_3}),
                            0
                           ]))).

-define(expected_sign_string_v13_sha256,
        iolist_to_binary(io_lib:format(
                           "Method:~s\nHashed Path:~s\n"
                           "X-Ops-Content-Hash:~s\n"
                           "X-Ops-Sign:algorithm=~s;version=~s\n"
                           "X-Ops-Timestamp:~s\n"
                           "X-Ops-UserId:~s\n"
                           "X-Ops-Server-API-Version:~B",
                           ["POST", ?hashed_path_sha256, ?hashed_body_sha256,
                            ?SIGNING_ALGORITHM_SHA256, ?SIGNING_VERSION_V1_3,
                            ?request_time_iso8601,
                            chef_authn:hash_string(?user,
                                                   {?SIGNING_ALGORITHM_SHA256,
                                                    ?SIGNING_VERSION_V1_3}),
                            1
                           ]))).

accepted_signing_protocol_test() ->
    %% All signing versions should accept default
    ?assertEqual(true, chef_authn:accepted_signing_protocol(default, ?SIGNING_VERSION_V1_0)),
    ?assertEqual(true, chef_authn:accepted_signing_protocol(default, ?SIGNING_VERSION_V1_1)),
    ?assertEqual(true, chef_authn:accepted_signing_protocol(default, ?SIGNING_VERSION_V1_2)),
    ?assertEqual(true, chef_authn:accepted_signing_protocol(default, ?SIGNING_VERSION_V1_3)),

    %% v1.0 supports only SHA1
    ?assertEqual(true, chef_authn:accepted_signing_protocol(?SIGNING_ALGORITHM_SHA1, ?SIGNING_VERSION_V1_0)),
    ?assertEqual(false, chef_authn:accepted_signing_protocol(?SIGNING_ALGORITHM_SHA256, ?SIGNING_VERSION_V1_0)),
    ?assertEqual(false, chef_authn:accepted_signing_protocol(<<"foo">>, ?SIGNING_VERSION_V1_0)),

    %% v1.1 supports only SHA1
    ?assertEqual(true, chef_authn:accepted_signing_protocol(?SIGNING_ALGORITHM_SHA1, ?SIGNING_VERSION_V1_1)),
    ?assertEqual(false, chef_authn:accepted_signing_protocol(?SIGNING_ALGORITHM_SHA256, ?SIGNING_VERSION_V1_1)),
    ?assertEqual(false, chef_authn:accepted_signing_protocol(<<"foo">>, ?SIGNING_VERSION_V1_1)),

    %% v1.2 supports only SHA1
    ?assertEqual(true, chef_authn:accepted_signing_protocol(?SIGNING_ALGORITHM_SHA1, ?SIGNING_VERSION_V1_2)),
    ?assertEqual(false, chef_authn:accepted_signing_protocol(?SIGNING_ALGORITHM_SHA256, ?SIGNING_VERSION_V1_2)),
    ?assertEqual(false, chef_authn:accepted_signing_protocol(<<"foo">>, ?SIGNING_VERSION_V1_2)),

    %% v1.3 supports SHA1 and SHA256
    ?assertEqual(true, chef_authn:accepted_signing_protocol(?SIGNING_ALGORITHM_SHA1, ?SIGNING_VERSION_V1_3)),
    ?assertEqual(true, chef_authn:accepted_signing_protocol(?SIGNING_ALGORITHM_SHA256, ?SIGNING_VERSION_V1_3)),
    ?assertEqual(false, chef_authn:accepted_signing_protocol(<<"foo">>, ?SIGNING_VERSION_V1_3)).


canonical_path_test_() ->
    Tests = [{<<"/">>, <<"/">>},
             {<<"////">>, <<"/">>},
             {<<"///">>, <<"/">>},
             {<<"/a/b/c">>, <<"/a/b/c">>},
             {<<"/a/b/c/">>, <<"/a/b/c">>},
             {<<"//a/b//c//">>, <<"/a/b/c">>},
             {<<"//a/b///c///">>, <<"/a/b/c">>},
             {<<"/a/b/c/?a=1&b=2">>, <<"/a/b/c">>},
             {<<"/a/b/c?a=1&b=2">>, <<"/a/b/c">>}
            ],
    [ ?_assertEqual({P, Expect}, {P, chef_authn:canonical_path(P)})
      || {P, Expect} <- Tests ].

hashed_path_sha1_test() ->
    ?assertEqual(?hashed_path_sha1, chef_authn:hash_string(chef_authn:canonical_path(?path))).

hashed_path_sha1_query_params_are_ignored_test() ->
    %% for X-Ops_sign: version=1.0, query params are not included in
    %% the hash of the path for request verification.
    ?assertEqual(?hashed_path_sha1, chef_authn:hash_string(chef_authn:canonical_path(?path_with_query))).

hashed_body_test() ->
    TestCases = [
                 {{?SIGNING_ALGORITHM_SHA1, ?SIGNING_VERSION_V1_0}, ?hashed_body_sha1},
                 {{?SIGNING_ALGORITHM_SHA1, ?SIGNING_VERSION_V1_1}, ?hashed_body_sha1},
                 {{?SIGNING_ALGORITHM_SHA1, ?SIGNING_VERSION_V1_2}, ?hashed_body_sha1},
                 {{?SIGNING_ALGORITHM_SHA1, ?SIGNING_VERSION_V1_3}, ?hashed_body_sha1},
                 {{?SIGNING_ALGORITHM_SHA256, ?SIGNING_VERSION_V1_3}, ?hashed_body_sha256}
                ],
    hashed_body_test_helper(TestCases).

hashed_body_test_helper([]) ->
    ok;
hashed_body_test_helper([{SignInfo, ExpectedHash} | T]) ->
    ?assertEqual(ExpectedHash, chef_authn:hashed_body(?body, SignInfo)),
    {ok, Fd} = file:open("../test/example_cert.pem", [read]),
    FileHash = chef_authn:hashed_body(Fd, SignInfo),
    {ok, Bin} = file:read_file("../test/example_cert.pem"),
    ContentHashFromBin = chef_authn:hashed_body(Bin, SignInfo),
    ContentHashFromList = chef_authn:hashed_body(binary_to_list(Bin), SignInfo),
    ?assert(is_binary(FileHash)),
    ?assertEqual(ContentHashFromBin, FileHash),
    ?assertEqual(ContentHashFromList, FileHash),
    hashed_body_test_helper(T).

signing_algorithm_test() ->
    ?assertEqual(<<"sha1">>, chef_authn:default_signing_algorithm()),
    ?assertEqual(true, chef_authn:accepted_signing_algorithm(<<"sha1">>)),
    ?assertEqual(false, chef_authn:accepted_signing_algorithm(<<"sha256">>)),
    ?assertEqual(false, chef_authn:accepted_signing_algorithm("")),
    ?assertEqual(false, chef_authn:accepted_signing_algorithm("sha1")).

signing_version_test() ->
    ?assertEqual(<<"1.1">>, chef_authn:default_signing_version()),
    ?assertEqual(true, chef_authn:accepted_signing_version(<<"1.1">>)),
    ?assertEqual(true, chef_authn:accepted_signing_version(<<"1.0">>)),
    ?assertEqual(true, chef_authn:accepted_signing_version(<<"1.2">>)),
    ?assertEqual(true, chef_authn:accepted_signing_version(<<"1.3">>)),
    ?assertEqual(false, chef_authn:accepted_signing_version(1.0)),
    ?assertEqual(false, chef_authn:accepted_signing_version("1.0")).

canonicalize_request_v1_0_test() ->
    Algorithm = chef_authn:default_signing_algorithm(),
    Version = <<"1.0">>,
    Val1 = chef_authn:canonicalize_request(?hashed_body_sha1, ?user, <<"post">>, ?request_time_iso8601, ?path,
                                           Algorithm, Version, undefined),
    ?assertEqual(?expected_sign_string_v10, Val1),

    % verify normalization
    Val2 = chef_authn:canonicalize_request(?hashed_body_sha1, ?user, <<"post">>, ?request_time_iso8601,
                                <<"/organizations/clownco/">>, Algorithm, Version, undefined),
    ?assertEqual(?expected_sign_string_v10, Val2).

canonicalize_request_v_1_1_test() ->
    Algorithm = chef_authn:default_signing_algorithm(),
    Version = <<"1.1">>,
    Val1 = chef_authn:canonicalize_request(?hashed_body_sha1, ?user, <<"post">>, ?request_time_iso8601, ?path,
                                           Algorithm, Version, undefined),
    ?assertEqual(?expected_sign_string_v11, Val1),

    % verify normalization
    Val2 = chef_authn:canonicalize_request(?hashed_body_sha1, ?user, <<"post">>, ?request_time_iso8601, ?path,
                                Algorithm, Version, undefined),
    ?assertEqual(?expected_sign_string_v11, Val2).

canonicalize_request_v_1_2_test() ->
    Algorithm = chef_authn:default_signing_algorithm(),
    Version = <<"1.2">>,
    Val1 = chef_authn:canonicalize_request(?hashed_body_sha1, ?user, <<"post">>, ?request_time_iso8601, ?path,
                                           Algorithm, Version, undefined),
    ?assertEqual(?expected_sign_string_v12, Val1),

    % verify normalization
    Val2 = chef_authn:canonicalize_request(?hashed_body_sha1, ?user, <<"post">>, ?request_time_iso8601, ?path,
                                           Algorithm, Version, undefined),
    ?assertEqual(?expected_sign_string_v12, Val2).

canonicalize_request_v_1_3_sha1_test() ->
    Algorithm = ?SIGNING_ALGORITHM_SHA1,
    Version = <<"1.3">>,
    GetHeader = fun(<<"X-Ops-Server-API-Version">>) ->
                       <<"1">>;
                  (_) ->
                       undefined
               end,
    Val1 = chef_authn:canonicalize_request(?hashed_body_sha1, ?user, <<"post">>, ?request_time_iso8601, ?path,
                                           Algorithm, Version, GetHeader),
    ?assertEqual(?expected_sign_string_v13_sha1, Val1),

    % verify that default server api version is 0
    Val2 = chef_authn:canonicalize_request(?hashed_body_sha1, ?user, <<"post">>, ?request_time_iso8601, ?path,
                                           Algorithm, Version, undefined),
    ?assertEqual(?expected_sign_string_v13_sha1_api_default, Val2).

canonicalize_request_v_1_3_sha256_test() ->
    Algorithm = ?SIGNING_ALGORITHM_SHA256,
    Version = <<"1.3">>,
    GetHeader = fun(<<"X-Ops-Server-API-Version">>) ->
                        <<"1">>;
                   (_) ->
                        undefined
                end,
    Val1 = chef_authn:canonicalize_request(?hashed_body_sha256, ?user, <<"post">>, ?request_time_iso8601, ?path,
                                           Algorithm, Version, GetHeader),
    ?assertEqual(?expected_sign_string_v13_sha256, Val1),

    % verify normalization
    Val2 = chef_authn:canonicalize_request(?hashed_body_sha256, ?user, <<"post">>, ?request_time_iso8601, ?path,
                                           Algorithm, Version, GetHeader),
    ?assertEqual(?expected_sign_string_v13_sha256, Val2).


sign_request_1_0_test() ->
    Algorithm = chef_authn:default_signing_algorithm(),
    Version = <<"1.0">>,
    {ok, RawKey} = file:read_file("../test/private_key"),
    Private_key = chef_authn:extract_private_key(RawKey),
    AuthLine = fun(I) -> lists:nth(I, ?X_OPS_AUTHORIZATION_LINES_V1_0) end,
    EXPECTED_SIGN_RESULT =
        [
         {"X-Ops-Content-Hash", ?X_OPS_CONTENT_HASH},
         {"X-Ops-UserId", ?X_OPS_USERID},
         {"X-Ops-Sign", "version=1.0"},
         {"X-Ops-Timestamp", ?request_time_iso8601},
         {"X-Ops-Authorization-1", AuthLine(1)},
         {"X-Ops-Authorization-2", AuthLine(2)},
         {"X-Ops-Authorization-3", AuthLine(3)},
         {"X-Ops-Authorization-4", AuthLine(4)},
         {"X-Ops-Authorization-5", AuthLine(5)},
         {"X-Ops-Authorization-6", AuthLine(6)}
        ],
    Sig = chef_authn:sign_request(Private_key, ?body, ?user, <<"post">>,
                                  ?request_time_erlang, ?path, Algorithm, Version),
    ?assertEqual(EXPECTED_SIGN_RESULT, Sig).

sign_request_1_1_test() ->
    Algorithm = chef_authn:default_signing_algorithm(),
    Version = <<"1.1">>,
    {ok, RawKey} = file:read_file("../test/private_key"),
    Private_key = chef_authn:extract_private_key(RawKey),
    AuthLine = fun(I) -> lists:nth(I, ?X_OPS_AUTHORIZATION_LINES_V1_1) end,
    EXPECTED_SIGN_RESULT =
        [
         {"X-Ops-Content-Hash", ?X_OPS_CONTENT_HASH},
         {"X-Ops-UserId", ?X_OPS_USERID},
         {"X-Ops-Sign", "version=1.1"},
         {"X-Ops-Timestamp", ?request_time_iso8601},
         {"X-Ops-Authorization-1", AuthLine(1)},
         {"X-Ops-Authorization-2", AuthLine(2)},
         {"X-Ops-Authorization-3", AuthLine(3)},
         {"X-Ops-Authorization-4", AuthLine(4)},
         {"X-Ops-Authorization-5", AuthLine(5)},
         {"X-Ops-Authorization-6", AuthLine(6)}
        ],
    Sig = chef_authn:sign_request(Private_key, ?body, ?user, <<"post">>,
                                  ?request_time_erlang, ?path, Algorithm, Version),
    ?assertEqual(EXPECTED_SIGN_RESULT, Sig).

sign_request_1_2_test() ->
    Algorithm = chef_authn:default_signing_algorithm(),
    Version = <<"1.2">>,
    {ok, RawKey} = file:read_file("../test/private_key"),
    Private_key = chef_authn:extract_private_key(RawKey),
    AuthLine = fun(I) -> lists:nth(I, ?X_OPS_AUTHORIZATION_LINES_V1_2) end,
    EXPECTED_SIGN_RESULT =
        [
         {"X-Ops-Content-Hash", ?X_OPS_CONTENT_HASH},
         {"X-Ops-UserId", ?X_OPS_USERID},
         {"X-Ops-Sign", "version=1.2"},
         {"X-Ops-Timestamp", ?request_time_iso8601},
         {"X-Ops-Authorization-1", AuthLine(1)},
         {"X-Ops-Authorization-2", AuthLine(2)},
         {"X-Ops-Authorization-3", AuthLine(3)},
         {"X-Ops-Authorization-4", AuthLine(4)},
         {"X-Ops-Authorization-5", AuthLine(5)},
         {"X-Ops-Authorization-6", AuthLine(6)}
        ],
    Sig = chef_authn:sign_request(Private_key, ?body, ?user, <<"post">>,
                       ?request_time_erlang, ?path, Algorithm, Version),
    ?assertEqual(EXPECTED_SIGN_RESULT, Sig).

sign_request_1_3_sha1_test() ->
    Algorithm = <<"sha1">>,
    Version = <<"1.3">>,
    {ok, RawKey} = file:read_file("../test/private_key"),
    Private_key = chef_authn:extract_private_key(RawKey),
    AuthLine = fun(I) -> lists:nth(I, ?X_OPS_AUTHORIZATION_LINES_V1_3_SHA1) end,
    EXPECTED_SIGN_RESULT =
        [
         {"X-Ops-Content-Hash", ?X_OPS_CONTENT_HASH},
         {"X-Ops-UserId", ?X_OPS_USERID},
         {"X-Ops-Sign", "algorithm=sha1;version=1.3"},
         {"X-Ops-Timestamp", ?request_time_iso8601},
         {"X-Ops-Authorization-1", AuthLine(1)},
         {"X-Ops-Authorization-2", AuthLine(2)},
         {"X-Ops-Authorization-3", AuthLine(3)},
         {"X-Ops-Authorization-4", AuthLine(4)},
         {"X-Ops-Authorization-5", AuthLine(5)},
         {"X-Ops-Authorization-6", AuthLine(6)}
        ],

    GetHeader = fun(<<"X-Ops-Server-API-Version">>) ->
                   <<"1">>;
              (_) ->
                   undefined
           end,

    Sig = chef_authn:sign_request({Algorithm, Version}, [
                               {private_key, Private_key},
                               {body, ?body},
                               {user, ?user},
                               {method, <<"post">>},
                               {time, ?request_time_erlang},
                               {path, ?path},
                               {get_header, GetHeader}
                              ]),
    ?assertEqual(EXPECTED_SIGN_RESULT, Sig).

sign_request_1_3_sha256_test() ->
    Algorithm = <<"sha256">>,
    Version = <<"1.3">>,
    {ok, RawKey} = file:read_file("../test/private_key"),
    Private_key = chef_authn:extract_private_key(RawKey),
    AuthLine = fun(I) -> lists:nth(I, ?X_OPS_AUTHORIZATION_LINES_V1_3_SHA256) end,
    EXPECTED_SIGN_RESULT =
        [
         {"X-Ops-Content-Hash", ?X_OPS_CONTENT_HASH_SHA256},
         {"X-Ops-UserId", ?X_OPS_USERID},
         {"X-Ops-Sign", "algorithm=sha256;version=1.3"},
         {"X-Ops-Timestamp", ?request_time_iso8601},
         {"X-Ops-Authorization-1", AuthLine(1)},
         {"X-Ops-Authorization-2", AuthLine(2)},
         {"X-Ops-Authorization-3", AuthLine(3)},
         {"X-Ops-Authorization-4", AuthLine(4)},
         {"X-Ops-Authorization-5", AuthLine(5)},
         {"X-Ops-Authorization-6", AuthLine(6)}
        ],

    GetHeader = fun(<<"X-Ops-Server-API-Version">>) ->
                   <<"1">>;
              (_) ->
                   undefined
           end,

    Sig = chef_authn:sign_request({Algorithm, Version}, [
                                   {private_key, Private_key},
                                   {body, ?body},
                                   {user, ?user},
                                   {method, <<"post">>},
                                   {time, ?request_time_erlang},
                                   {path, ?path},
                                   {get_header, GetHeader}
                                  ]),
    ?assertEqual(EXPECTED_SIGN_RESULT, Sig).

sign_bogus_request_test() ->
    ?assertError({missing_required_data, _},
                 chef_authn:sign_request(fake_private, ?body, undefined, undefined,
                                         ?request_time_erlang, ?path,
                                         chef_authn:default_signing_algorithm(),
                                         <<"1.1">>)).

key_type_cert_test() ->
    {ok, Public_key} = file:read_file("../test/example_cert.pem"),
    ?assertEqual(cert, chef_authn:key_type(Public_key)).

key_type_pk_test() ->
    {ok, Public_key} = file:read_file("../test/platform_public_key_example.pem"),
    ?assertEqual(key, chef_authn:key_type(Public_key)).

key_type_spki_pk_test() ->
    {ok, Public_key} = file:read_file("../test/spki_public.pem"),
    ?assertEqual(key, chef_authn:key_type(Public_key)).

decrypt_sig_test() ->
    AuthSig = iolist_to_binary(?X_OPS_AUTHORIZATION_LINES_V1_0),
    {ok, Public_key} = file:read_file("../test/example_cert.pem"),
    ?assertEqual(?expected_sign_string_v10,
                 chef_authn:decrypt_sig(AuthSig, Public_key)).

decrypt_sig_v1_1_test() ->
    AuthSig = iolist_to_binary(?X_OPS_AUTHORIZATION_LINES_V1_1),
    {ok, Public_key} = file:read_file("../test/example_cert.pem"),
    DecryptSig = chef_authn:decrypt_sig(AuthSig, Public_key),
    ?assertEqual(?expected_sign_string_v11, DecryptSig).

verify_sig_v1_2_test() ->
    Sig = iolist_to_binary(?X_OPS_AUTHORIZATION_LINES_V1_2),
    Plain = ?expected_sign_string_v12,
    {ok, Public_key} = file:read_file("../test/example_cert.pem"),
    ?assertEqual({name,<<"spec-user">>},
                 chef_authn:verify_sig(Plain, ignore, ignore,
                                       Sig,
                                       list_to_binary(?X_OPS_USERID),
                                       Public_key,
                                       {<<"sha1">>, <<"1.2">>})).

verify_sig_v1_3_sha1_test() ->
    Sig = iolist_to_binary(?X_OPS_AUTHORIZATION_LINES_V1_3_SHA1),
    Plain = ?expected_sign_string_v13_sha1,
    {ok, Public_key} = file:read_file("test/example_cert.pem"),
    ?assertEqual({name,<<"spec-user">>},
                 chef_authn:verify_sig(Plain, ignore, ignore,
                                       Sig,
                                       list_to_binary(?X_OPS_USERID),
                                       Public_key,
                                       {<<"sha1">>, <<"1.3">>})).

verify_sig_v1_3_sha256_test() ->
    Sig = iolist_to_binary(?X_OPS_AUTHORIZATION_LINES_V1_3_SHA256),
    Plain = ?expected_sign_string_v13_sha256,
    {ok, Public_key} = file:read_file("test/example_cert.pem"),
    ?assertEqual({name,<<"spec-user">>},
                 chef_authn:verify_sig(Plain, ignore, ignore,
                                       Sig,
                                       list_to_binary(?X_OPS_USERID),
                                       Public_key,
                                       {<<"sha256">>, <<"1.3">>})).


fetch_keys(BaseDir, Filenames) ->
    Keys = [{N,K} || {N, {ok, K}} <-  [ {Name, file:read_file(iolist_to_binary([ BaseDir, Name]))} || Name <- Filenames ] ],
    Keys.

%% [ iolist_to_binary([ BaseDir, Name]) || Name <- Filenames ]

verify_sigs_v1_2_test_() ->
    Sig = iolist_to_binary(?X_OPS_AUTHORIZATION_LINES_V1_2),
    Plain = ?expected_sign_string_v12,
    KeyList = fetch_keys("../test/", ?KEYFILES),
    [ fun() ->
              %% Test key in front of list
              AuthN = chef_authn:verify_sigs(Plain, ignore, ignore,
                                             Sig,
                                             list_to_binary(?X_OPS_USERID),
                                             KeyList,
                                             {<<"sha1">>, <<"1.2">>}),
              ?assertEqual({name,<<"spec-user">>, "example_cert.pem"}, AuthN)
      end,
      fun() ->
              %% Test key in back of list
              KeyList2 = lists:reverse(KeyList),
              AuthN = chef_authn:verify_sigs(Plain, ignore, ignore,
                                             Sig,
                                             list_to_binary(?X_OPS_USERID),
                                             KeyList2,
                                             {<<"sha1">>, <<"1.2">>}),
              ?debugVal(AuthN),
              ?assertEqual({name,<<"spec-user">>, "example_cert.pem"}, AuthN)
      end,
      fun() ->
              %% Test no key
              [_|KeyList2] = KeyList,
              ?assertError({badmatch, false},
                               chef_authn:verify_sigs(Plain, ignore, ignore,
                                                      Sig,
                                                      list_to_binary(?X_OPS_USERID),
                                                      KeyList2,
                                                      {<<"sha1">>, <<"1.2">>}))
      end
    ].


decrypt_tagged_sig_test() ->
    AuthSig = iolist_to_binary(?X_OPS_AUTHORIZATION_LINES_V1_0),
    {ok, Public_key} = file:read_file("../test/example_cert.pem"),
    ?assertEqual(?expected_sign_string_v10,
                 chef_authn:decrypt_sig(AuthSig, Public_key)).

decrypt_sig_fail_platform_style_test() ->
    AuthSig = iolist_to_binary(?X_OPS_AUTHORIZATION_LINES_V1_0),
    {ok, Public_key} = file:read_file("../test/platform_public_key_example.pem"),
    ?assertError(decrypt_failed, chef_authn:decrypt_sig(AuthSig, {key, Public_key})).

decrypt_sig_fail_spki_test() ->
    AuthSig = iolist_to_binary(?X_OPS_AUTHORIZATION_LINES_V1_0),
    {ok, Public_key} = file:read_file("../test/spki_public.pem"),
    ?assertError(decrypt_failed, chef_authn:decrypt_sig(AuthSig, {key, Public_key})).

make_skew_time() ->
    % force time skew to allow for now
    ReqTimeEpoch = calendar:datetime_to_gregorian_seconds(
                     chef_time_utils:time_iso8601_to_date_time(?request_time_iso8601)),
    NowEpoch = calendar:datetime_to_gregorian_seconds(
                 calendar:now_to_universal_time(os:timestamp())),
    (NowEpoch - ReqTimeEpoch) + 100.

authenticate_user_request_no_body_test_() ->
    {ok, RawKey} = file:read_file("../test/private_key"),
    Private_key = chef_authn:extract_private_key(RawKey),
    {ok, Public_key} = file:read_file("../test/example_cert.pem"),
    Headers0 = chef_authn:sign_request(Private_key, ?user, <<"get">>,
                                       now, ?path),
    %% We convert here back into binary keys in headers since that
    %% is what we'd get when parsing the received headers over the wire
    Headers = [{list_to_binary(K), list_to_binary(V)} || {K, V} <- Headers0],
    GetHeader = fun(X) -> proplists:get_value(X, Headers) end,
    % force time skew to allow a request to be processed 'now'
    [fun() ->
             Ok = chef_authn:authenticate_user_request(GetHeader, <<"get">>, ?path, <<>>,
                                                       Public_key, 600),
              ?assertEqual({name, ?user}, Ok)
     end].

authenticate_user_request_1_3_test_() ->
    authenticate_user_request_tests_by_version(<<"1.3">>).

authenticate_user_request_1_2_test_() ->
    authenticate_user_request_tests_by_version(<<"1.2">>).

authenticate_user_request_1_1_test_() ->
    authenticate_user_request_tests_by_version(<<"1.1">>).

authenticate_user_request_1_0_test_() ->
    authenticate_user_request_tests_by_version(<<"1.0">>).

%% These tests exercice chef_uathn:authenticate_user_request/6 parameterized by the signing
%% protocol version. As long as chef_authn:sign_request/8 supports signing, these tests
%% should work.
authenticate_user_request_tests_by_version(SignVersion) ->
    {ok, RawKey} = file:read_file("../test/private_key"),
    Private_key = chef_authn:extract_private_key(RawKey),
    {ok, Public_key} = file:read_file("../test/example_cert.pem"),
    Alg = chef_authn:default_signing_algorithm(),
    Headers0 = chef_authn:sign_request(Private_key, ?body, ?user, <<"post">>,
                                       ?request_time_erlang, ?path, Alg, SignVersion),
    %% We convert here back into binary keys in headers since that
    %% is what we'd get when parsing the received headers over the wire
    Headers = [{list_to_binary(K), list_to_binary(V)} || {K, V} <- Headers0],
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

     {"no_authn: invalid time",
      fun() ->
              MyHeader = fun(<<"X-Ops-Timestamp">>) ->
                                 <<"Tue Apr  9 20:11:33 PDT 2013">>; % not valid format
                            (H) ->
                                 GetHeader(H)
                         end,
              BadTime = chef_authn:authenticate_user_request(MyHeader, <<"post">>, ?path,
                                                             ?body, Public_key, TimeSkew),
              ?assertEqual({no_authn,{bad_headers,[<<"X-Ops-Timestamp">>]}},
                            BadTime)
      end
      },

     {"no_authn: bad key",
      fun() ->
              {ok, Other_key} = file:read_file("../test/other_cert.pem"),
              BadKey = chef_authn:authenticate_user_request(GetHeader, <<"post">>, ?path,
                                                 ?body, Other_key,
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
    Headers0 = chef_authn:sign_request(Private_key, ?body, ?user, <<"post">>,
                                       calendar:universal_time(), ?path),
    %% We convert here back into binary keys in headers since that
    %% is what we'd get when parsing the received headers over the wire
    Headers = [{list_to_binary(K), V} || {K, V} <- Headers0],
    GetHeader = fun(X) -> proplists:get_value(X, Headers) end,
    MissingOneTests =
        [ fun() ->
                  Headers2 = proplists:delete(H, Headers),
                  GetHeader2 = fun(X) -> proplists:get_value(X, Headers2) end,
                  ?assertThrow({missing_headers, [H]}, chef_authn:validate_headers(GetHeader2, 10))
          end || H <- ?REQUIRED_HEADERS ],
    [{algorithm, _SignAlgorithm}, {version, SignVersion}] = chef_authn:validate_headers(GetHeader, 10),
    [?_assertEqual(chef_authn:default_signing_version(), SignVersion),
     ?_assertThrow({missing_headers, ?REQUIRED_HEADERS},
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

extract_pem_encoded_public_key_test_() ->
    [{"CERTIFICATE",
      fun() ->
              {ok, Pem} = file:read_file("../test/example_cert.pem"),
              Key = chef_authn:extract_pem_encoded_public_key(Pem),
              ?assertMatch(<<"-----BEGIN PUBLIC KEY",_Bin/binary>>, Key)
      end},
     {"PUBLIC KEY",
      fun() ->
              {ok, Pem} = file:read_file("../test/spki_public.pem"),
              Key = chef_authn:extract_pem_encoded_public_key(Pem),
              ?assertEqual({error, bad_key}, Key)
      end},
     {"RSA PUBLIC KEY",
      fun() ->
              {ok, Pem} = file:read_file("../test/webui_pub.pem"),
              Key = chef_authn:extract_pem_encoded_public_key(Pem),
              ?assertEqual({error, bad_key}, Key)
      end},
     {"RSA PRIVATE KEY",
      fun() ->
              {ok, Pem} = file:read_file("../test/private_key"),
              Key = chef_authn:extract_pem_encoded_public_key(Pem),
              ?assertEqual({error, bad_key}, Key)
      end},
     {"invalid cert returns error tuple", generator,
      fun() ->

              {ok, Pem} = file:read_file("../test/example_cert.pem"),
              Pem2 = re:replace(Pem, "D", "0", [{return, binary}]),
              {ok, Priv} = file:read_file("../test/private_key"),
              BadKeys = [Priv, Pem2, <<"">>, <<"abc">>,
                         term_to_binary([123, {x, x}])],
              [ ?_assertEqual({error, bad_key},
                              chef_authn:extract_pem_encoded_public_key(K))

                || K <- BadKeys ]
      end}

    ].



extract_public_or_private_key_test_() ->
    [{"RSA PUBLIC KEY",
      fun() ->
              {ok, Pem} = file:read_file("../test/webui_pub.pem"),
              Key = chef_authn:extract_public_or_private_key(Pem),
              ?assert(Key#'RSAPublicKey'.modulus > 0)
      end},

     {"PUBLIC KEY",
      fun() ->
              {ok, Pem} = file:read_file("../test/spki_public.pem"),
              Key = chef_authn:extract_public_or_private_key(Pem),
              ?assert(Key#'RSAPublicKey'.modulus > 0)
      end},

     {"CERTIFICATE",
      fun() ->
              {ok, Pem} = file:read_file("../test/example_cert.pem"),
              Key = chef_authn:extract_public_or_private_key(Pem),
              ?assert(Key#'RSAPublicKey'.modulus > 0)
      end},

     {"RSA PRIVATE KEY",
      fun() ->
              {ok, Pem} = file:read_file("../test/private_key"),
              Key = chef_authn:extract_public_or_private_key(Pem),
              ?assert(Key#'RSAPrivateKey'.prime1 > 0)
      end},

     {"RSA PRIVATE KEY PKCS#8",
      fun() ->
              {ok, Pem} = file:read_file("../test/private_key_pkcs8"),
              Key = chef_authn:extract_public_or_private_key(Pem),
              ?assert(Key#'RSAPrivateKey'.prime1 > 0)
      end},

     {"UNSUPPORTED DSA PRIVATE KEY PKCS#8",
      fun() ->
              {ok, Pem} = file:read_file("../test/private_key_pkcs8_dsa"),
              Key = chef_authn:extract_public_or_private_key(Pem),
              ?_assertEqual({error, bad_key}, Key)
      end},

     {"invalid keys return error tuple", generator,
      fun() ->
              %% mangle a key
              {ok, Pem} = file:read_file("../test/spki_public.pem"),
              Pem2 = re:replace(Pem, "A", "0", [{return, binary}]),
              BadKeys = [Pem2, <<"">>, <<"abc">>,
                         term_to_binary([123, {x, x}])],
              [ ?_assertEqual({error, bad_key},
                              chef_authn:extract_public_or_private_key(K))
                || K <- BadKeys ]
      end}
    ].

extract_public_key_test_() ->
    [{"RSA PUBLIC KEY",
      fun() ->
              {ok, Pem} = file:read_file("../test/webui_pub.pem"),
              Key = chef_authn:extract_public_key(Pem),
              ?assert(Key#'RSAPublicKey'.modulus > 0)
      end},

     {"PUBLIC KEY",
      fun() ->
              {ok, Pem} = file:read_file("../test/spki_public.pem"),
              Key = chef_authn:extract_public_key(Pem),
              ?assert(Key#'RSAPublicKey'.modulus > 0)
      end},

     {"CERTIFICATE",
      fun() ->
              {ok, Pem} = file:read_file("../test/example_cert.pem"),
              Key = chef_authn:extract_public_key(Pem),
              ?assert(Key#'RSAPublicKey'.modulus > 0)
      end},

     {"RSA PRIVATE KEY is",
      fun() ->
              {ok, Pem} = file:read_file("../test/private_key"),
              Key = chef_authn:extract_public_or_private_key(Pem),
              ?assert(Key#'RSAPrivateKey'.prime1 > 0)
      end},

     {"invalid keys return error tuple", generator,
      fun() ->
              %% mangle a key
              {ok, Pem} = file:read_file("../test/spki_public.pem"),
              Pem2 = re:replace(Pem, "A", "0", [{return, binary}]),
              {ok, Priv} = file:read_file("../test/private_key"),
              BadKeys = [Priv, Pem2, <<"">>, <<"abc">>,
                         term_to_binary([123, {x, x}])],
              [ ?_assertEqual({error, bad_key},
                              chef_authn:extract_public_key(K))
                || K <- BadKeys ]
      end}
    ].

extract_private_key_test_() ->
    [{"RSA PRIVATE KEY",
      fun() ->
              {ok, Pem} = file:read_file("../test/private_key"),
              Key = chef_authn:extract_private_key(Pem),
              ?assert(Key#'RSAPrivateKey'.prime1 > 0)
      end},

     {"invalid keys return error tuple", generator,
      fun() ->
              %% mangle a key
              {ok, Pem} = file:read_file("../test/spki_public.pem"),
              Munged = re:replace(Pem, "A", "0", [{return, binary}]),
              {ok, Cert} = file:read_file("../test/example_cert.pem"),
              {ok, Pub1} = file:read_file("../test/webui_pub.pem"),
              {ok, Pub2} = file:read_file("../test/spki_public.pem"),
              BadKeys = [Munged, Cert, Pub1, Pub2,
                         <<"">>, <<"abc">>,
                         term_to_binary([123, {x, x}])],
              [ ?_assertEqual({error, bad_key},
                              chef_authn:extract_private_key(K))
                || K <- BadKeys ]
      end}
    ].

hash_file_test() ->
    {ok, Fd} = file:open("../test/example_cert.pem", [read]),
    FileHash = chef_authn:hash_file(Fd),
    {ok, Bin} = file:read_file("../test/example_cert.pem"),
    ContentHash = chef_authn:hash_string(Bin),
    ?assert(is_binary(FileHash)),
    ?assertEqual(ContentHash, FileHash).


