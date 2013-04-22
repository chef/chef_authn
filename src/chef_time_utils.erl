%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92 -*-
%% ex: ts=4 sw=4 et
%% @author Seth Falcon <seth@opscode.com>
%% @author Christopher Brown <cb@opscode.com>
%% @copyright 2011-2012 Opscode, Inc. All Rights Reserved.
%% @doc chef_time_utils - helpers for converting between http and erlang time
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

-module(chef_time_utils).

-export([time_iso8601/1,
         time_iso8601_to_date_time/1,
         canonical_time/1,
         time_in_bounds/2,
         time_in_bounds/3
        ]).

-include("chef_time_utils.hrl").

%% @doc Converts Erlang time-tuple to iso8601 formatted date string.
%%
%% Example output looks like `<<"2003-12-13T18:30:02Z">>'
-spec(time_iso8601(erlang_time() | 'now') -> binary()).
time_iso8601(now) ->
    time_iso8601(calendar:universal_time());
time_iso8601({{Year, Month, Day}, {Hour, Min, Sec}}) ->
    % Is there a way to build a binary straight away?
    Fmt = "~4B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0BZ",
    iolist_to_binary(io_lib:format(Fmt,
                                   [Year, Month, Day,
                                    Hour, Min, Sec])).

%% @doc Convert an iso8601 time string to Erlang date time
%% representation.
-spec(time_iso8601_to_date_time(string()|binary()) -> erlang_time()).
time_iso8601_to_date_time(ATime) when is_binary(ATime) ->
    time_iso8601_to_date_time(binary_to_list(ATime));
time_iso8601_to_date_time(ATime) ->
    [Year, Month, Day, Hour, Min, Sec] =
        [ list_to_integer(S) || S <- string:tokens(ATime, "-T:Z") ],
    {{Year, Month, Day}, {Hour, Min, Sec}}.

-spec(canonical_time(string() | binary()) -> iso8601_time()).
%% @doc Convert a string or binary HTTP request time to iso8601 format
canonical_time(T) when is_binary(T) ->
    canonical_time(binary_to_list(T));
canonical_time(T) when is_list(T) ->
    time_iso8601(httpd_util:convert_request_date(T)).

-spec time_in_bounds(undefined | string() | binary(), time_skew()) -> boolean() | invalid_reqtime.
%% @doc Check if a time, expressed as an ISO8601 string is equal to the current time, within
%% a given Skew interval.
%%
%% Returns invalid_reqtime if the ISO8601 time can't be parsed
time_in_bounds(undefined, _Skew) ->
    false;
time_in_bounds(ReqTime, Skew) ->
    Now = calendar:now_to_universal_time(os:timestamp()),
    try
        time_in_bounds(chef_time_utils:time_iso8601_to_date_time(ReqTime), Now, Skew)
    catch
        error:_ ->
            invalid_reqtime
    end.

-spec time_in_bounds(erlang_time(), erlang_time(), time_skew() ) -> boolean().
%% @doc Check if two times are equal within a given Skew interval.
%%
time_in_bounds(T1, T2, Skew) when is_integer(Skew) ->
    S1 = calendar:datetime_to_gregorian_seconds(T1),
    S2 = calendar:datetime_to_gregorian_seconds(T2),
    (S2 - S1) < Skew.


