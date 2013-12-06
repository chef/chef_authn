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

-define(BUF_SIZE, 16384).

-define(DEFAULT_SIGNING_ALGORITHM, <<"sha1">>).

-define(SIGNING_VERSION_V1_0, <<"1.0">>).
-define(SIGNING_VERSION_V1_1, <<"1.1">>).
-define(SIGNING_VERSION_V1_2, <<"1.2">>).

%% version 1.2 incorporates the related but slightly different RSA PKCS 1.5 SHA+RSA signing method
-define(SIGNING_VERSIONS, [?SIGNING_VERSION_V1_0, ?SIGNING_VERSION_V1_1, ?SIGNING_VERSION_V1_2]).

-define(SIGNING_VERSION_KEY, <<"version">>).

-define(SIGNING_ALGORITHM_KEY, <<"algorithm">>).

-define(VERSION1_SIG_FORMAT, <<"Method:~s\nHashed Path:~s\n"
                               "X-Ops-Content-Hash:~s\n"
                               "X-Ops-Timestamp:~s\nX-Ops-UserId:~ts">>).

-define(REQUIRED_HEADERS, [<<"X-Ops-UserId">>,
                           <<"X-Ops-Timestamp">>,
                           <<"X-Ops-Sign">>,
                           % FIXME: mixlib-authorization requires host, but
                           % it is not used as part of the signing protocol AFAICT
                           % <<"host">>,
                           <<"X-Ops-Content-Hash">>]).

-record(key_pair, {public_key :: binary(),
                   private_key :: binary()}).

