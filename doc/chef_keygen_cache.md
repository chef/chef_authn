

# Module chef_keygen_cache #
* [Description](#description)
* [Function Index](#index)
* [Function Details](#functions)


chef_keygen_cache Precreates RSA key pairs and servers them when you ask.
__Behaviours:__ [`gen_server`](gen_server.md).
<a name="description"></a>

## Description ##



chef_keygen_cache is a gen_server that keeps a configurable number of RSA key pairs on
hand for fast delivery. You can configure how many workers are used to replinish the key
cache when it drops below the desired size. If you request a key when the cache is empty,
the atom `keygen_timeout` is returned immediately.


You can control the behavior of the key cache using the following app config keys:

* keygen_cache_size: The number of keys to store in the cache

* keygen_start_size: The number of keys that must be available in the cache before
completing startup and accepting requests. Cache startup blocks until `keygen_start_size`
keys are available in the cache.

* keygen_timeout: Time allowed for the external key generation command (openssl). A
timeout atom is returned if the command takes longer than `Timeout` milliseconds. This
value is also used to bound the time allowed for the cache gen_server to respond to key
request calls

* keygen_cache_workers: The number of workers available to generate key pairs. This
should never be larger than the number of logical CPUs. Defaults to larger of 1 and half
the number of logical processors as reported by `erlang:system_info(logical_processors)`

* keygen_size: Size in bits of the RSA keys to generate. Defaults to 2048. Mostly used
to speed up testing.

<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#code_change-3">code_change/3</a></td><td></td></tr><tr><td valign="top"><a href="#get_key_pair-0">get_key_pair/0</a></td><td>Retrieve an RSA key pair from the cache.</td></tr><tr><td valign="top"><a href="#handle_call-3">handle_call/3</a></td><td></td></tr><tr><td valign="top"><a href="#handle_cast-2">handle_cast/2</a></td><td></td></tr><tr><td valign="top"><a href="#handle_info-2">handle_info/2</a></td><td></td></tr><tr><td valign="top"><a href="#init-1">init/1</a></td><td></td></tr><tr><td valign="top"><a href="#start_link-0">start_link/0</a></td><td></td></tr><tr><td valign="top"><a href="#status-0">status/0</a></td><td>Return a proplist of status information about the state of the key cache.</td></tr><tr><td valign="top"><a href="#stop-0">stop/0</a></td><td></td></tr><tr><td valign="top"><a href="#terminate-2">terminate/2</a></td><td></td></tr><tr><td valign="top"><a href="#update_config-0">update_config/0</a></td><td>Instruct the cache to reread app config values.</td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="code_change-3"></a>

### code_change/3 ###

`code_change(OldVsn, State, Extra) -> any()`


<a name="get_key_pair-0"></a>

### get_key_pair/0 ###


<pre><code>
get_key_pair() -&gt; {PublicKey::binary(), PrivateKey::binary()} | keygen_timeout
</code></pre>

<br></br>



Retrieve an RSA key pair from the cache.


The return value is a tuple of the form `{PublicKey, PrivateKey}` where each element is a
binary containing the PEM encoded key. If no keys are available in the cache or if the
cache takes longer than the timeout value specified in app config `{chef_authn,
kegen_timeout, Timeout}`, then the atom `keygen_timeout` is returned.
<a name="handle_call-3"></a>

### handle_call/3 ###

`handle_call(Request, From, State) -> any()`


<a name="handle_cast-2"></a>

### handle_cast/2 ###

`handle_cast(Request, State) -> any()`


<a name="handle_info-2"></a>

### handle_info/2 ###

`handle_info(Key_pair, State) -> any()`


<a name="init-1"></a>

### init/1 ###

`init(X1) -> any()`


<a name="start_link-0"></a>

### start_link/0 ###

`start_link() -> any()`


<a name="status-0"></a>

### status/0 ###


<pre><code>
status() -&gt; [{atom(), term()}]
</code></pre>

<br></br>


Return a proplist of status information about the state of the key cache.
<a name="stop-0"></a>

### stop/0 ###

`stop() -> any()`


<a name="terminate-2"></a>

### terminate/2 ###

`terminate(Reason, State) -> any()`


<a name="update_config-0"></a>

### update_config/0 ###


<pre><code>
update_config() -&gt; ok
</code></pre>

<br></br>


Instruct the cache to reread app config values.
