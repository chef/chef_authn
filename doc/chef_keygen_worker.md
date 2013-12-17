

# Module chef_keygen_worker #
* [Description](#description)
* [Function Index](#index)
* [Function Details](#functions)


chef_keygen_worker makes RSA key pairs just for you.
__Behaviours:__ [`gen_server`](gen_server.md).
<a name="description"></a>

## Description ##



chef_keygen_worker is a single-use worker gen_server. When started, it generates an RSA
key pair and stores it in server state. Calling [`get_key_pair/1`](#get_key_pair-1) will return the
generated key pair and terminate the worker.



Instead of relying on NIFs and correct use of libopenssl, this code shells out to openssl
to generate a private key and then uses functions in the public_key module to extract and
encode the public key. The call to the openssl command line utility is done via open_port
and requires message passing. For this reason, the call is made inside init to avoid
issues from misuse of this single key pair worker.


Basic use is:

```
  {ok, Pid} = chef_keygen_worker:start_link(),
  #key_pair{public_key = Pub, private_key = Priv} = chef_keygen_worker:get_key_pair(Pid)
```


There are two app config keys you can use to control the behavior of this worker. The key
`keygen_size` determines the RSA key size in bits to generate. If not specified, the
default is 2048. For use with the Chef authentication protocol, you should not use a key
size less than 2048. Since key generation is a CPU intensive task, the operation is
carried out under a timeout configured via `keygen_timeout`. If a key generation takes
longer than this value (default is 1000 ms) then the atom `keygen_timeout` is returned
instead of a key. Both values are read from app config on each invocation.
<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#code_change-3">code_change/3</a></td><td></td></tr><tr><td valign="top"><a href="#get_key_pair-1">get_key_pair/1</a></td><td></td></tr><tr><td valign="top"><a href="#handle_call-3">handle_call/3</a></td><td></td></tr><tr><td valign="top"><a href="#handle_cast-2">handle_cast/2</a></td><td></td></tr><tr><td valign="top"><a href="#handle_info-2">handle_info/2</a></td><td></td></tr><tr><td valign="top"><a href="#init-1">init/1</a></td><td></td></tr><tr><td valign="top"><a href="#start_link-1">start_link/1</a></td><td></td></tr><tr><td valign="top"><a href="#terminate-2">terminate/2</a></td><td></td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="code_change-3"></a>

### code_change/3 ###

`code_change(OldVsn, State, Extra) -> any()`


<a name="get_key_pair-1"></a>

### get_key_pair/1 ###


<pre><code>
get_key_pair(Pid::pid()) -&gt; #key_pair{} | keygen_timeout
</code></pre>

<br></br>



<a name="handle_call-3"></a>

### handle_call/3 ###

`handle_call(Request, From, KeyPair) -> any()`


<a name="handle_cast-2"></a>

### handle_cast/2 ###

`handle_cast(Request, State) -> any()`


<a name="handle_info-2"></a>

### handle_info/2 ###

`handle_info(Info, State) -> any()`


<a name="init-1"></a>

### init/1 ###

`init(X1) -> any()`


<a name="start_link-1"></a>

### start_link/1 ###

`start_link(Config) -> any()`


<a name="terminate-2"></a>

### terminate/2 ###

`terminate(Reason, State) -> any()`


