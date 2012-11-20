

-type calendar_time() :: { non_neg_integer(),  non_neg_integer(),  non_neg_integer() }.
-type calendar_date() :: { integer(),  1..12, 1..31 }.
-type erlang_time() :: {calendar_date(), calendar_time()}.

-type http_time() :: binary().
-type iso8601_time() :: binary().

-type time_skew() :: pos_integer().         % in seconds

