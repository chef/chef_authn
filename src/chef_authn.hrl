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

-define(buf_size, 16384).

-define(default_signing_algorithm, <<"sha1">>).

-define(signing_version_v1_0, <<"1.0">>).
-define(signing_version_v1_1, <<"1.1">>).
-define(signing_version_v1_2, <<"1.2">>).

-define(signing_versions, [?signing_version_v1_0, ?signing_version_v1_1, ?signing_version_v1_2]).

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
