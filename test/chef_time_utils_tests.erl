%% -*- erlang-indent-level: 4;indent-tabs-mode: nil; fill-column: 92 -*-
%% ex: ts=4 sw=4 et
%% @author Seth Falcon <seth@opscode.com>
%% @author Christopher Brown <cb@opscode.com>
%% @doc Tests for chef_time_utils - Request signing and authentication for Opscode Chef


-module(chef_time_utils_tests).

-include_lib("eunit/include/eunit.hrl").

-define(request_time_http, <<"Thu, 01 Jan 2009 12:00:00 GMT">>).
-define(request_time_iso8601, <<"2009-01-01T12:00:00Z">>).

canonical_time_test() ->
    % This date format comes from Ruby's default printing,
    % but doesn't correspond to the HTTP rfc2616 format
    % Time = "Thu Jan 01 12:00:00 -0000 2009",
    ?assertEqual(?request_time_iso8601, chef_time_utils:canonical_time(?request_time_http)).

time_in_bounds_test() ->
    T1 = {{2011,1,26},{2,3,0}},

    % test seconds
    T2 = {{2011,1,26},{2,3,4}},
    ?assertEqual(false, chef_time_utils:time_in_bounds(T1, T2, 2)),
    ?assertEqual(true, chef_time_utils:time_in_bounds(T1, T2, 5)),

    % test minutes
    T3 = {{2011,1,26},{2,6,0}},
    ?assertEqual(false, chef_time_utils:time_in_bounds(T1, T3, 60*2)),
    ?assertEqual(true, chef_time_utils:time_in_bounds(T1, T3, 60*5)),

    % test hours
    T4 = {{2011,1,26},{4,0,0}},
    ?assertEqual(false, chef_time_utils:time_in_bounds(T1, T4, 60*60)),
    ?assertEqual(true, chef_time_utils:time_in_bounds(T1, T4, 60*60*3)).

%% We expect no function match when Skew is undefined
undefined_skew_test() ->
    T1 = {{2011,1,26},{2,3,0}},
    T2 = {{2011,1,26},{2,3,4}},

    ?assertError(function_clause, chef_time_utils:time_in_bounds(T1, T2, undefined)).

