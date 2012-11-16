%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92 -*-
%% ex: ts=4 sw=4 et
%% @author Seth Falcon <seth@opscode.com>
%% @author Christopher Brown <cb@opscode.com>
%% @copyright 2011 Opscode, Inc.
%%

-type calendar_time() :: { non_neg_integer(),  non_neg_integer(),  non_neg_integer() }.
-type calendar_date() :: { integer(),  1..12, 1..31 }.

-type header_name() :: binary().
-type header_value() :: binary() | 'undefined'.
-type get_header_fun() :: fun((header_name()) -> header_value()).
-type http_body() :: binary() | pid().
-type user_id() :: binary().
-type http_method() :: <<_:24,_:_*8>>. %% Covers <<"GET">> through <<"DELETE">>, <<"OPTIONS">> not supported
-type http_time() :: binary().
-type iso8601_time() :: binary().
-type http_path() :: binary().
-type sha_hash64() :: binary().
-type signing_algorithm() :: binary().
-type signing_version() :: binary().
-type erlang_time() :: {calendar_date(), calendar_time()}.
-type base64_binary() :: <<_:64,_:_*8>>.
-type public_key_data() :: {cert, base64_binary()} | {key, base64_binary()}|base64_binary().
-type header_fun() :: fun((header_name()) -> header_value()).
-type time_skew() :: pos_integer().         % in seconds
%% -type rsa_public_key() :: public_key:rsa_public_key().

-define(signing_algorithm, <<"sha1">>).

-define(signing_version, <<"1.0">>).

-define(signing_version_v1_1, <<"1.1">>).

-define(signing_version_v1_0, <<"1.0">>).

-define(signing_versions, [?signing_version_v1_0, ?signing_version]).

-define(signing_version_key, <<"version">>).

-define(signing_algorithm_key, <<"algorithm">>).

-define(version1_sig_format, <<"Method:~s\nHashed Path:~s\n"
                               "X-Ops-Content-Hash:~s\n"
                               "X-Ops-Timestamp:~s\nX-Ops-UserId:~ts">>).

-define(required_headers, [<<"X-Ops-UserId">>,
                           <<"X-Ops-Timestamp">>,
                           <<"X-Ops-Sign">>,
                           % FIXME: mixlib-authorization requires host, but
                           % it is not used as part of the signing protocol AFAICT
                           % <<"host">>,
                           <<"X-Ops-Content-Hash">>]).

