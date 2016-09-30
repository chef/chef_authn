%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92 -*-
%% ex: ts=4 sw=4 et
%% @author Seth Falcon <seth@opscode.com>
%% @author Christopher Brown <cb@opscode.com>
%% @doc chef_authn - Request signing and authentication for Opscode Chef
%%
%% This module is an Erlang port of the mixlib-authentication Ruby gem.
%% It can be used to sign HTTP requests to send to a Chef server or to
%% validate such requests (for server implementation).
%%
%% Copyright 2011-2012 Opscode, Inc. All Rights Reserved.
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

-module(chef_authn).
-include_lib("eunit/include/eunit.hrl").
-include("chef_time_utils.hrl").

-include("chef_authn.hrl").

-export([default_signing_algorithm/1,
         accepted_signing_protocol/2,
         default_signing_version/0,
         accepted_signing_version/1,
         extract_public_or_private_key/1,
         extract_private_key/1,
         extract_public_key/1,
         extract_pem_encoded_public_key/1,
         sign_request/2,
         sign_request/5,
         sign_request/6,
         sign_request/8,
         authenticate_user_request/6,
         validate_headers/2
         ]).

% deprecated
-export([accepted_signing_algorithm/1,
         default_signing_algorithm/0,
         hash_string/1,
         hash_file/1
        ]).

-include_lib("public_key/include/public_key.hrl").

-type header_name() :: binary().
-type header_value() :: binary() | 'undefined'.
-type get_header_fun() :: fun((header_name()) -> header_value()).
-type http_body() :: binary() | pid().
-type user_id() :: binary().
-type http_method() :: binary().
-type http_path() :: binary().
-type sha_hash64() :: binary().
-type signing_algorithm() :: <<_:32>>.
-type signing_version() :: <<_:24>>.
-type base64_binary() :: <<_:64,_:_*8>>.
-type public_key_data() :: {cert, base64_binary()} | {key, base64_binary()} | base64_binary().

-type rsa_private_key() :: #'RSAPrivateKey'{}.
-type rsa_public_key() :: #'RSAPublicKey'{}.

-type key_desc() :: any().
-type public_key_list() :: [{key_desc(), public_key_data() | rsa_public_key()}].

-type header_fun() :: fun((header_name()) -> header_value()).
-type sign_parameter() :: {private_key, rsa_private_key()} |
                          {body, http_body()} |
                          {user, user_id()} |
                          {method, http_method()} |
                          {time, erlang_time() | now} |
                          {path, http_path()} |
                          {get_header, header_fun()}.


-ifdef(TEST).
-compile([export_all]).
-endif.

-spec signing_protocols_for_version(SignVersion :: binary()) -> [signing_algorithm()] | undefined.
signing_protocols_for_version(SignVersion) when SignVersion =:= ?SIGNING_VERSION_V1_0;
                                                SignVersion =:= ?SIGNING_VERSION_V1_1;
                                                SignVersion =:= ?SIGNING_VERSION_V1_2 ->
    [?SIGNING_ALGORITHM_SHA1];
signing_protocols_for_version(?SIGNING_VERSION_V1_3) ->
    [?SIGNING_ALGORITHM_SHA256];
signing_protocols_for_version(_) ->
    undefined.

%% @doc Return the default signing algorithm
%% @deprecated use default_signing_algorithm/1
-spec default_signing_algorithm() -> signing_algorithm().
default_signing_algorithm() ->
    ?DEFAULT_SIGNING_ALGORITHM.

%% @doc Return the default signing algorithm for the specified Version
-spec default_signing_algorithm(SignVersion :: binary()) -> signing_algorithm() | {error, missing_version}.
default_signing_algorithm(SignVersion) ->
    case signing_protocols_for_version(SignVersion) of
        undefined ->
            {error, missing_version};
        [Default|_SupportedAlgorithms] ->
            Default
    end.

%% @doc Is the signing algorithm valid?
%% of {unknown_algorithm, Algorithm}
%% @deprecated use accepted_signing_protocol/2 instead
-spec accepted_signing_algorithm(Algorithm :: binary()) -> boolean().
accepted_signing_algorithm(Algorithm) ->
    Algorithm =:= ?DEFAULT_SIGNING_ALGORITHM.

%% @doc Return the default signing version
-spec default_signing_version() ->  signing_version().
default_signing_version() ->
    ?SIGNING_VERSION_V1_1.

%% @doc Is the signing version acceptable for chef request.  Returns true if so, else false.
-spec accepted_signing_version(SignVersion :: binary()) -> boolean().
accepted_signing_version(SignVersion) ->
    signing_protocols_for_version(SignVersion) =/= undefined.

%% @doc Is the signing version and algorithm acceptable for chef request.  Returns true if so, else false.
-spec accepted_signing_protocol(SignAlgorithm :: binary() | default, SignVersion :: binary()) -> boolean().
accepted_signing_protocol(default, SignVersion) ->
    accepted_signing_version(SignVersion);
accepted_signing_protocol(SignAlgorithm, SignVersion) ->
    case signing_protocols_for_version(SignVersion) of
        undefined ->
            false;
        SupportedAlgorithms ->
            lists:member(SignAlgorithm, SupportedAlgorithms)
    end.

-spec process_key({'RSAPublicKey',  binary(), _} |
                  {'RSAPrivateKey', binary(), _} |
                  {'PrivateKeyInfo', _, _}       |
                  {'SubjectPublicKeyInfo', _, _}) ->
                         rsa_public_key() |
                         rsa_private_key() |
                         {error, bad_key}.
process_key({'SubjectPublicKeyInfo', _, _} = PubEntry) ->
    public_key:pem_entry_decode(PubEntry);
process_key({'RSAPublicKey', Der, _}) ->
    public_key:der_decode('RSAPublicKey', Der);
process_key({'RSAPrivateKey', Der, _}) ->
        public_key:der_decode('RSAPrivateKey', Der);
process_key({'Certificate', _Der, _} = CertEntry) ->
    %% NOTE: assumes the certificate contains public key info and only extracts that.
    Cert = public_key:pem_entry_decode(CertEntry),
    TbsCert = Cert#'Certificate'.tbsCertificate,
    Spki = TbsCert#'TBSCertificate'.subjectPublicKeyInfo,
    {0, KeyDer} = Spki#'SubjectPublicKeyInfo'.subjectPublicKey,
    public_key:der_decode('RSAPublicKey', KeyDer);
process_key({'PrivateKeyInfo', _, _} = Entry) ->
    KeyInfo = public_key:pem_entry_decode(Entry),
    KeyAlgorithmInfo = KeyInfo#'PrivateKeyInfo'.privateKeyAlgorithm,
    case KeyAlgorithmInfo of
        #'PrivateKeyInfo_privateKeyAlgorithm'{algorithm=?'rsaEncryption'} ->
            PrivateKey = KeyInfo#'PrivateKeyInfo'.privateKey,
            public_key:der_decode('RSAPrivateKey', list_to_binary(PrivateKey));
        _ ->
            {error, bad_key}
    end.

%% @doc Given PEM content as binary, return either an RSA public or private key record (or
%% error tuple). The PEM can contain an RSA public key in PKCS1, SPKI (X509), or an X509
%% certificate wrapping an SPKI formatted key. Note that private keys will not be extracted
%% from X509 certificate data.
-spec extract_public_or_private_key(binary()) -> rsa_public_key()  |
                                                 rsa_private_key() |
                                                 {error, bad_key}.
extract_public_or_private_key(RawKey) ->
    try
        [Key] = public_key:pem_decode(RawKey),
        process_key(Key)
    catch
        _:_ ->
            {error, bad_key}
    end.

-spec extract_public_key(binary()) -> rsa_public_key() | {error, bad_key}.
extract_public_key(RawKey) ->
    case extract_public_or_private_key(RawKey) of
        #'RSAPublicKey'{} = Key ->
            Key;
        _ ->
            {error, bad_key}
    end.

-spec extract_private_key(binary()) -> rsa_private_key() | {error, bad_key}.
extract_private_key(RawKey) ->
    case extract_public_or_private_key(RawKey) of
        #'RSAPrivateKey'{} = Key ->
            Key;
        _ ->
            {error, bad_key}
    end.

%% @doc Given PEM X509 certificate as a binary, return the RSA public key
%% in PEM format. If the argument is not a certificate, bad_key will be returned.
-spec extract_pem_encoded_public_key(binary()) -> binary() | {error, bad_key}.
extract_pem_encoded_public_key( <<"-----BEGIN CERTIFICATE", _Bin/binary>> = RawCert) ->
    try
        DecodedPublicKey = extract_public_key(RawCert),
        EncodedEntry = public_key:pem_entry_encode('SubjectPublicKeyInfo', DecodedPublicKey),
        public_key:pem_encode([EncodedEntry])
    catch
        _:_ ->
            {error, bad_key}
    end;
extract_pem_encoded_public_key(_) ->
    {error, bad_key}.


-spec(hash_string(string()|binary()) -> sha_hash64()).
%% @doc Base 64 encoded SHA1 of `Str'
%% @deprecated This is an internal function
hash_string(Str) ->
    base64:encode(crypto:hash(sha, Str)).

-spec(hash_string(string()|binary(), {signing_algorithm(), signing_version()}) -> sha_hash64()).
%% @doc Base 64 encoded SHA1 of `Str'
hash_string(Str, {_, SignVersion}) when SignVersion =:= ?SIGNING_VERSION_V1_0;
                                        SignVersion =:= ?SIGNING_VERSION_V1_1;
                                        SignVersion =:= ?SIGNING_VERSION_V1_2
                                        ->
    base64:encode(crypto:hash(sha, Str));
hash_string(Str, {?SIGNING_ALGORITHM_SHA256, ?SIGNING_VERSION_V1_3}) ->
    base64:encode(crypto:hash(sha256, Str)).


-spec(hash_file(pid()) -> sha_hash64()).
%% @doc Base 64 encoded SHA1 of contents of `F', which must be the pid of a file
%% @deprecated This is an internal function and stop being exposed
hash_file(F) ->
    hash_file_finish(F, crypto:hash_init(sha)).

-spec(hash_file(pid(), {signing_algorithm(), signing_version()}) -> sha_hash64()).
%% @doc Base 64 encoded checksum of contents of `F', which must be the pid of a file
hash_file(F, {_, SignVersion}) when SignVersion =:= ?SIGNING_VERSION_V1_0;
                                    SignVersion =:= ?SIGNING_VERSION_V1_1;
                                    SignVersion =:= ?SIGNING_VERSION_V1_2
                                    ->
    hash_file_finish(F, crypto:hash_init(sha));
hash_file(F, {?SIGNING_ALGORITHM_SHA256, ?SIGNING_VERSION_V1_3}) ->
    hash_file_finish(F, crypto:hash_init(sha256)).

-spec hash_file_finish(file:io_device(), _) -> sha_hash64().
hash_file_finish(F, Ctx) ->
    case io:get_chars(F, "", ?BUF_SIZE) of
        eof ->
            base64:encode(crypto:hash_final(Ctx));
        Data ->
            hash_file_finish(F, crypto:hash_update(Ctx, Data))
    end.


%% @doc Canonicalize an HTTP request path by removing doubled slashes
%% and trailing slash (except for case of root path).
-spec canonical_path(binary()) -> binary().
canonical_path(Path = <<"/">>) ->
    Path;
canonical_path(Path) ->
    %% remove query parameters
    Path1 = re:replace(Path, "\\?.*$", "", [{return, binary}]),
    NoDoubles = re:replace(Path1, "/+/", <<"/">>, [{return, binary}, global]),
    case re:replace(NoDoubles, "/$", "", [{return, binary}]) of
        <<"">> -> <<"/">>;
        P      -> P
    end.


%% @doc Canonicalize HTTP method as all uppercase binary

canonical_method(Method) ->
    list_to_binary(string:to_upper(binary_to_list(Method))).

-spec(hashed_body(binary() | pid(), {signing_algorithm(), signing_version()}) -> binary()).
%% @doc Return the SHA1 hash of the body which can either be a binary
%% or the pid of a file.
hashed_body(Body, SignInfo) when is_pid(Body) ->
    hash_file(Body, SignInfo);
hashed_body(Body, SignInfo) when is_binary(Body) ->
    hash_string(Body, SignInfo);
hashed_body(Body, SignInfo) when is_list(Body) ->
    hashed_body(iolist_to_binary(Body), SignInfo).

-spec(canonicalize_request(sha_hash64(), user_id(), http_method(), iso8601_time(),
                           http_path(), signing_algorithm(), signing_version(), header_fun())
      -> binary()).
%% @doc Canonicalize an HTTP request into a binary that can be signed
%% for verification.
%%
%% NOTE: this function assumes that `Time' is already in canonical
%% form (see chef_time_utils:canonical_time/1).  Other arguments are canonicalized.
%%
canonicalize_request(BodyHash, UserId, _Method, Time, _Path, _SignAlgorithm, _SignVersion, _GetHeader)
  when BodyHash =:= undefined orelse
         UserId =:= undefined orelse
           Time =:= undefined ->
    erlang:error({missing_required_data, {BodyHash, UserId, Time}});
canonicalize_request(BodyHash, UserId, Method, Time, Path, SignAlgorithm, SignVersion, _GetHeader)
  when SignVersion =:= ?SIGNING_VERSION_V1_0;
       SignVersion =:= ?SIGNING_VERSION_V1_1;
       SignVersion =:= ?SIGNING_VERSION_V1_2 ->
    Format = ?VERSION1_SIG_FORMAT,
    CanonicalUserId = canonicalize_userid(UserId, {SignAlgorithm, SignVersion}),
    iolist_to_binary(io_lib:format(Format, [canonical_method(Method),
                                            hash_string(canonical_path(Path), {SignAlgorithm, SignVersion}),
                                            BodyHash,
                                            Time,
                                            CanonicalUserId]));
canonicalize_request(BodyHash, UserId, Method, Time, Path, SignAlgorithm,
                     ?SIGNING_VERSION_V1_3=SignVersion, GetHeader) ->
    Format = ?VERSION1_3_SIG_FORMAT,
    CanonicalUserId = canonicalize_userid(UserId, {SignAlgorithm, SignVersion}),
    ServerApiVersion = case GetHeader of
        undefined -> ?DEFAULT_SERVER_API_VERSION;
        HeaderFun -> case HeaderFun(<<"X-Ops-Server-API-Version">>) of
                         undefined -> ?DEFAULT_SERVER_API_VERSION;
                         Version -> binary_to_integer(Version)
                     end
    end,
    iolist_to_binary(io_lib:format(Format, [canonical_method(Method),
                                            canonical_path(Path),
                                            BodyHash,
                                            SignVersion,
                                            Time,
                                            CanonicalUserId,
                                            ServerApiVersion])).

canonicalize_userid(UserId, {_, SignVersion}=SignInfo)
  when SignVersion =:= ?SIGNING_VERSION_V1_1;
       SignVersion =:= ?SIGNING_VERSION_V1_2 ->
            hash_string(UserId, SignInfo);
canonicalize_userid(UserId, {_, SignVersion})
  when SignVersion =:= ?SIGNING_VERSION_V1_0;
       SignVersion =:= ?SIGNING_VERSION_V1_3 ->
    UserId.

-spec create_signature(binary(), rsa_private_key(),
                       {signing_algorithm(), signing_version()}) ->  binary().
create_signature(SignThis, PrivateKey, {_, SignVersion}) when SignVersion =:= ?SIGNING_VERSION_V1_0;
                                                         SignVersion =:= ?SIGNING_VERSION_V1_1 ->
    public_key:encrypt_private(SignThis, PrivateKey);
create_signature(SignThis, PrivateKey, {_, ?SIGNING_VERSION_V1_2}) ->
    public_key:sign(SignThis, sha, PrivateKey);
create_signature(SignThis, PrivateKey, {?SIGNING_ALGORITHM_SHA256, ?SIGNING_VERSION_V1_3}) ->
    public_key:sign(SignThis, sha256, PrivateKey).

-spec sign_request(rsa_private_key(), user_id(), http_method(),
                   erlang_time() | now, http_path()) -> [{[any()],[any()]}].
%% @doc Sign an HTTP request without a body (primarily GET)
%% @deprecated Use sign_request/2 instead.
sign_request(PrivateKey, User, Method, Time, Path) ->
    SignVersion = default_signing_version(),
    SignAlgorithm = default_signing_algorithm(SignVersion),
    sign_request(PrivateKey, <<"">>, User, Method, Time, Path, SignAlgorithm, SignVersion).

%% @doc Sign an HTTP request without a body (primarily GET)
%% @deprecated Use sign_request/2 instead.
-spec sign_request(rsa_private_key(), http_body(), user_id(),
                   http_method(), erlang_time() | now, http_path()) ->
                          [{[any()],[any()]}].
sign_request(PrivateKey, Body, User, Method, Time, Path) ->
    SignVersion = default_signing_version(),
    SignAlgorithm = default_signing_algorithm(SignVersion),
    sign_request(PrivateKey, Body, User, Method, Time, Path, SignAlgorithm, SignVersion).

%% @doc Sign an HTTP request so it can be sent to a Chef server.
%%
%% Returns a list of header tuples that should be included in the
%% final HTTP request.
%%
%% The keys are returned as strings to match with what is required by ibrowse. The values
%% are returned as binary().
%%
%% Note that the headers can't be passed directly to validate_headers which expects headers to
%% have binary keys (as returned from the ejson/jiffy parsing routines
%%
%% @deprecated Use sign_request/2 instead.
-spec sign_request(rsa_private_key(), http_body(), user_id(),
                   http_method(), erlang_time() | now, http_path(),
                   signing_algorithm(), signing_version()) ->
                          [{[any()],[any()]}].
sign_request(PrivateKey, Body, User, Method, Time, Path, SignAlgorithm, SignVersion) ->
    sign_request({SignAlgorithm, SignVersion},
                 [
                  {private_key, PrivateKey},
                  {body, Body},
                  {user, User},
                  {method, Method},
                  {time, Time},
                  {path, Path},
                  {get_header, undefined}
                 ]).

%% @doc Sign an HTTP request so it can be sent to a Chef server.
%%
%% Returns a list of header tuples that should be included in the
%% final HTTP request.
-spec sign_request({signing_algorithm(), signing_version()},
                   [sign_parameter()]) -> [{[any()],[any()]}].
sign_request({SignAlgorithm, SignVersion}=SignInfo, Options) ->
    [PrivateKey, Body, User, Method, Time,
     Path, GetHeader] = [proplists:get_value(X, Options) ||
                    X <- [private_key, body, user, method, time,
                          path, get_header]
                   ],
    CTime = time_iso8601(Time),
    HashedBody = hashed_body(Body, SignInfo),
    SignThis = canonicalize_request(HashedBody, User, Method, CTime, Path, SignAlgorithm, SignVersion, GetHeader),
    Sig = base64:encode(create_signature(SignThis, PrivateKey, SignInfo)),
    X_Ops_Sign = x_ops_sign_header_value(SignInfo),
    headers_as_str([{"X-Ops-Content-Hash", HashedBody},
                    {"X-Ops-UserId", User},
                    {"X-Ops-Sign", X_Ops_Sign},
                    {"X-Ops-Timestamp", CTime}]
                   ++ sig_header_items(Sig)).

%% @doc Return the header value for a given signature description
-spec x_ops_sign_header_value({signing_algorithm(), signing_version()}) -> binary().
x_ops_sign_header_value({_, SignVersion}) when SignVersion =:= ?SIGNING_VERSION_V1_0;
                                               SignVersion =:= ?SIGNING_VERSION_V1_1;
                                               SignVersion =:= ?SIGNING_VERSION_V1_2 ->
    iolist_to_binary(io_lib:format("version=~s", [SignVersion]));
x_ops_sign_header_value({SignAlgorithm, SignVersion}) when SignVersion =:= ?SIGNING_VERSION_V1_3 ->
    iolist_to_binary(io_lib:format("algorithm=~s;version=~s", [SignAlgorithm, SignVersion])).

%% @doc Return the time as an ISO8601 formatted string.  Accept the atom 'now'
%% as a argument to represent the current time
-spec time_iso8601(erlang_time() | now) -> binary().
time_iso8601(Time) ->
    Time0 = case Time of
        now ->
            calendar:universal_time();
        _Else ->
            Time
    end,
    chef_time_utils:time_iso8601(Time0).

headers_as_str(SignedHeaders) ->
    %% TODO: ibrowse requires that header names be atom or
    %% string, but values can be an iolist but not a raw binary.
    %% It might be worth investigating whether ibrowse can be taught how
    %% to handle header names and values that are binaries to avoid conversion.
    [{as_str(K), as_str(V)} || {K, V} <- SignedHeaders].

%% Helper for ensuring that all values passed to ibrowse in headers are lists
-spec as_str(binary() | list()) -> list().
as_str(V) when is_binary(V) ->
    binary_to_list(V);
as_str(V) when is_list(V) ->
    V.

%% @doc Generate X-Ops-Authorization-I for use in building auth headers
-spec xops_header(non_neg_integer()) -> header_name().
xops_header(I) ->
    iolist_to_binary(io_lib:format(<<"X-Ops-Authorization-~B">>, [I])).

%% @doc Given an encrypted signature base64 binary, split it up with
%% line feeds evry 60 characters and build up a list of
%% X-Ops-Authorization-i header tuples.
%%
-spec sig_header_items(binary()) -> [{binary(),binary()}].
sig_header_items(Sig) ->
    % Ruby's Base64.encode64 method inserts line feeds every 60
    % encoded characters.
    Lines = sig_to_list(Sig, 60),
    [ {xops_header(I), L} ||
        {L, I} <- lists:zip(Lines, lists:seq(1, length(Lines))) ].

%% @doc Split a binary into chunks of size N
%% -spec sig_to_list(binary(), pos_integer()) -> [binary()]. % TODO PROBLEMATIC
sig_to_list(Sig, N) ->
    lists:reverse(sig_to_list(Sig, N, [])).

-spec sig_to_list(binary(), 60, [<<_:480>>]) -> [binary(), ...].
sig_to_list(Sig, N, Acc) ->
    case iolist_size(Sig) =< N of
        true ->
            [Sig|Acc];
        false ->
            <<Line:N/binary, Rest/binary>> = Sig,
            sig_to_list(Rest, N, [Line|Acc])
    end.

%% @doc Validate that all required headers are present
%%
%% Returns 'ok' if all required headers are present.  Otherwise, throws
%% `{missing, [header_name()]}' providing a list of the
%% missing headers in the exception.
%%
%% @throws {missing, [binary()]} | bad_clock | bad_sign_desc
%%
-spec validate_headers(header_fun(), time_skew()) -> [{'algorithm',binary()} |
                                                      {'version',binary()},...].
validate_headers(GetHeader, TimeSkew) ->
    Missing = [ H || H <- ?REQUIRED_HEADERS, GetHeader(H) == undefined ],
    case Missing of
        [] ->
            validate_time_in_bounds(GetHeader, TimeSkew),
            validate_sign_description(GetHeader);
        TheList -> throw({missing_headers, TheList})
    end.

%% @doc Validate that the request time is within `TimeSkew' seconds of now.
%%
%% Returns 'ok' if request time in the X-Ops-Timestamp header is
%% wihtin bounds.  Otherwise, throws `bad_clock'
%%
%% @throws bad_clock
%%
-spec validate_time_in_bounds(header_fun(), time_skew()) -> 'ok' | no_return().
validate_time_in_bounds(GetHeader, TimeSkew) ->
    ReqTime = GetHeader(<<"X-Ops-Timestamp">>),
    case chef_time_utils:time_in_bounds(ReqTime, TimeSkew) of
        true -> ok;
        false -> throw(bad_clock);
        invalid_reqtime -> throw({bad_headers, [<<"X-Ops-Timestamp">>]})
    end.

%% @doc Validate that the X-Ops-Sign header describes a supported signing format.
%%
%% Returns 'ok' if the signing format is supported.  Otherwise, throws
%% `bad_sign_desc'
%%
%% @throws bad_sign_desc
%%
-spec validate_sign_description(header_fun()) -> [{'algorithm',binary()} |
                                                  {'version',binary()},...].
validate_sign_description(GetHeader) ->
    SignDesc = parse_signing_description(GetHeader(<<"X-Ops-Sign">>)),
    SignVersion = proplists:get_value(?SIGNING_VERSION_KEY, SignDesc),
    SignAlgorithm = proplists:get_value(?SIGNING_ALGORITHM_KEY, SignDesc, default),
    case accepted_signing_protocol(SignAlgorithm, SignVersion) of
        true ->
            [{algorithm, maybe_lookup_sign_algorithm(SignAlgorithm, SignVersion)},
             {version, SignVersion}];
        false ->
            throw(bad_sign_desc)
    end.

% If a algorithm was not specified, look up the default one for the given version
-spec maybe_lookup_sign_algorithm(signing_algorithm() | default, signing_version()) -> signing_algorithm().
maybe_lookup_sign_algorithm(default, SignVersion) ->
    default_signing_algorithm(SignVersion);
maybe_lookup_sign_algorithm(SignAlgorithm, _SignVersion) ->
    SignAlgorithm.

%% @doc Determine if a request is valid
%%
%% The `GetHeader' argument is a fun that closes over the request
%% headers and can be called to obtain the value of a header.  It
%% should either return the value of the header as binary or
%% 'undefined'.
%%
%% A request signed with a timestamp more than `TimeSkew' seconds from
%% now will not be authenticated.
%%
%% `PublicKey' is a binary containing an RSA public key in PEM format.
%%
-spec authenticate_user_request(get_header_fun(),
                                http_method(),
                                http_path(),
                                http_body(),
                                public_key_data() | rsa_public_key(),
                                time_skew()) ->
                       {name, user_id()} | {name, user_id(), key_desc()} | {no_authn, Reason::term()}.
authenticate_user_request(GetHeader, Method, Path, Body, PublicKey, TimeSkew) ->
    try
        do_authenticate_user_request(GetHeader, Method, Path, Body, PublicKey, TimeSkew)
    catch
        error:_ -> {no_authn, bad_sig};
        throw:Why -> {no_authn, Why}
    end.

-spec do_authenticate_user_request(get_header_fun(),
                   http_method(),
                   http_path(),
                   http_body(),
                   public_key_data() | rsa_public_key() | public_key_list(),
                   time_skew())
                  ->  {name, user_id()} | {name, user_id(), key_desc()}.

do_authenticate_user_request(GetHeader, Method, Path, Body, PublicKey, TimeSkew) ->
    % NOTE: signing description validation and time_skew validation
    % are done in the wrapper function.
    UserId = GetHeader(<<"X-Ops-UserId">>),
    ReqTime = GetHeader(<<"X-Ops-Timestamp">>),
    ContentHash = GetHeader(<<"X-Ops-Content-Hash">>),
    AuthSig = sig_from_headers(GetHeader, 1, []),
    [{algorithm, SignAlgorithm}, {version, SignVersion}] =  validate_headers(GetHeader, TimeSkew),
    BodyHash = hashed_body(Body, {SignAlgorithm, SignVersion}),
    Plain = canonicalize_request(BodyHash, UserId, Method, ReqTime,
                                 Path, SignAlgorithm, SignVersion, GetHeader),
    verify_sig_or_sigs(Plain, BodyHash, ContentHash, AuthSig, UserId, PublicKey, {SignAlgorithm, SignVersion}).


-spec verify_sig_or_sigs(binary(), binary(), binary(), binary(), binary(),
                         [{key_desc(), public_key_data() | rsa_public_key()}], {binary(), binary()}) ->
                                {name, user_id()} | {name, user_id(), key_desc()}.
verify_sig_or_sigs(Plain, BodyHash, ContentHash, AuthSig, UserId,  [Head | _] = KeyData, SignInfo)
  when is_tuple(Head) ->
    verify_sigs(Plain, BodyHash, ContentHash, AuthSig, UserId, KeyData, SignInfo);
verify_sig_or_sigs(Plain, BodyHash, ContentHash, AuthSig, UserId, KeyData, SignInfo) ->
    verify_sig(Plain, BodyHash, ContentHash, AuthSig, UserId, KeyData, SignInfo).


%% @doc Try sigs in order, returning key_id for the first one that validates correctly
%% The key_id is an identifier meaningful to the caller. (In our case it might be a tuple {name, userorclient, id, authz_id}
%% There are some optimization opportunities around hoisting more common stuff out of verify_sig to minimize
%% what we are repeating each step
%%
-spec verify_sigs(binary(), binary(), binary(), binary(), binary(),
                  [{key_desc(), public_key_data() | rsa_public_key()}], {binary(), binary()}) ->
                         {name, user_id(), key_desc()}.

verify_sigs(Plain, BodyHash, ContentHash, AuthSig, UserId, [{KeyId, PubKey}], SignInfo) ->
    {name, UserId} = verify_sig(Plain, BodyHash, ContentHash, AuthSig, UserId, PubKey, SignInfo),
    {name, UserId, KeyId};
verify_sigs(Plain, BodyHash, ContentHash, AuthSig, UserId, [{KeyId, PubKey} | Remaining], SignInfo) ->
    try
        {name, UserId} = verify_sig(Plain, BodyHash, ContentHash, AuthSig, UserId, PubKey, SignInfo),
        {name, UserId, KeyId}
    catch
        error:_Any ->
            verify_sigs(Plain, BodyHash, ContentHash, AuthSig, UserId, Remaining, SignInfo)
    end.

-spec verify_sig(binary(), binary(), binary(), binary(), binary(),
                 public_key_data() | rsa_public_key(), {binary(), binary()}) ->
                        {name, user_id()}.

verify_sig(Plain, BodyHash, ContentHash, AuthSig, UserId, PublicKey, {_, SignVersion})
  when SignVersion =:= ?SIGNING_VERSION_V1_0;
       SignVersion =:= ?SIGNING_VERSION_V1_1 ->
    Plain = decrypt_sig(AuthSig, PublicKey),
    %% the signing will also validate this, but since we require that the
    %% X-Ops-Content-Hash be sent, we should verify it. A TODO item is to move this
    %% check early in the request handling so that we error out before fetching key data
    %% if the content hash is wrong.
    ContentHash = BodyHash,
    {name, UserId};
verify_sig(Plain, _BodyHash, _ContentHash, AuthSig, UserId, PublicKey, {_, ?SIGNING_VERSION_V1_2}) ->
    true = public_key:verify(Plain, sha, base64:decode(AuthSig), decode_key_data(PublicKey)),
    {name, UserId};
verify_sig(Plain, _BodyHash, _ContentHash, AuthSig, UserId, PublicKey,
           {?SIGNING_ALGORITHM_SHA256, ?SIGNING_VERSION_V1_3}) ->
    true = public_key:verify(Plain, sha256,
                             base64:decode(AuthSig), decode_key_data(PublicKey)),
    {name, UserId}.

-spec decrypt_sig(binary(), public_key_data() | rsa_public_key()) -> binary().
decrypt_sig(Sig, {'RSAPublicKey', _, _} = PK) ->
        public_key:decrypt_public(base64:decode(Sig), PK);
decrypt_sig(Sig, KeyData) ->
    decrypt_sig(Sig, decode_key_data(KeyData)).

-spec sig_from_headers(get_header_fun(), non_neg_integer(), [any()]) ->
    binary().
sig_from_headers(GetHeader, I, Acc) ->
    Header = xops_header(I),
    case GetHeader(Header) of
        undefined ->
            iolist_to_binary(lists:reverse(Acc));
        Part ->
            sig_from_headers(GetHeader, I+1, [Part|Acc])
    end.

-spec parse_signing_description('undefined' | binary()) -> [{binary(),binary()}].
parse_signing_description(undefined) ->
    [];
parse_signing_description(Desc) ->
    [ {Key, Value} ||
        [Key, Value] <- [ re:split(KV, "=") || KV <- re:split(Desc, ";") ] ].

-spec decode_key_data(public_key_data()) -> rsa_public_key().
%% Decode a Base64 encoded public key which is either
%% wrapped in a certificate or a public key which can be in
%% PKCS1 or SPKI format. The PKCS1 format is deprecated within Chef, but
%% supported for read.
%%
%% For backwards compatibility we support the key_data to be provided through
%% the API as a tagged tuple as well as a binary()
decode_key_data({cert, Data}) ->
    decode_cert(Data);
decode_key_data({key, Data}) ->
    decode_public_key(Data);
decode_key_data(Data) when is_binary(Data) ->
    decode_key_data({key_type(Data), Data}).

-spec key_type(base64_binary()) -> cert | key.
%% For a given Base64 encoded public key determine if it's wrapped in
%% a certificate or is a raw public key.
key_type( <<"-----BEGIN CERTIFICATE", _Bin/binary>>) ->
    %% Cert
    cert;
key_type(<<"-----BEGIN PUBLIC KEY", _Bin/binary>>) ->
    %% SPKI
    key;
key_type(<<"-----BEGIN RSA PUBLIC KEY", _Bin/binary>>) ->
    %% PKCS1
    key.

-spec decode_public_key(binary() |
                      {'RSAPublicKey', binary(), _} |
                      {'SubjectPublicKeyInfo', _, _}) -> rsa_public_key().
decode_public_key({'RSAPublicKey', Der, _}) ->
    public_key:der_decode('RSAPublicKey', Der);
decode_public_key({'SubjectPublicKeyInfo', _, _} = PubEntry) ->
    public_key:pem_entry_decode(PubEntry);
decode_public_key(Bin) when is_binary(Bin) ->
    [Decode] = public_key:pem_decode(Bin),
    decode_public_key(Decode).

-spec decode_cert(binary()) -> rsa_public_key().
%% der_decode only spec's term
%% decode a Base64 encoded certificate and return the public key
decode_cert(Bin) ->
    Cert = public_key:pem_entry_decode(hd(public_key:pem_decode(Bin))),
    TbsCert = Cert#'Certificate'.tbsCertificate,
    Spki = TbsCert#'TBSCertificate'.subjectPublicKeyInfo,
    {0, KeyDer} = Spki#'SubjectPublicKeyInfo'.subjectPublicKey,
    public_key:der_decode('RSAPublicKey', KeyDer).
