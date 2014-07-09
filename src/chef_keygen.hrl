-define(DEFAULT_KEY_SIZE, 2048).
-define(DEFAULT_KEY_TIMEOUT, 1000).
-define(DEFAULT_CACHE_SIZE, 10).
%% milliseconds to pause between key generation calls when filling the cache. We use
%% gen_server's timeout mechanism so this really represents the length of time to pause when
%% the server is idle. This is appropriate because if clients are making key requests and
%% we're not full, there's little benefit to blocking the server to fill it rather than
%% simply serving those requests with inline keygen.
-define(DEFAULT_KEYGEN_PAUSE, 200).

-define(TIMEOUT_PAD, 1000).
