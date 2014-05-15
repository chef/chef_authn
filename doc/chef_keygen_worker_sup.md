

# Module chef_keygen_worker_sup #
* [Description](#description)
* [Function Index](#index)
* [Function Details](#functions)


supervisor for chef_keygen_worker throw-away key generator processs.
__Behaviours:__ [`supervisor`](supervisor.md).
<a name="description"></a>

## Description ##


Example:

```
  chef_keygen_worker_sup:start_link().
  {ok, Pid} = chef_keygen_worker_sup:new_worker(),
  chef_keygen_worker:get_key_pair(Pid).
```

<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#init-1">init/1</a></td><td></td></tr><tr><td valign="top"><a href="#new_worker-0">new_worker/0</a></td><td></td></tr><tr><td valign="top"><a href="#new_worker-1">new_worker/1</a></td><td></td></tr><tr><td valign="top"><a href="#start_link-0">start_link/0</a></td><td></td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="init-1"></a>

### init/1 ###

`init(X1) -> any()`


<a name="new_worker-0"></a>

### new_worker/0 ###

`new_worker() -> any()`


<a name="new_worker-1"></a>

### new_worker/1 ###

`new_worker(Pid) -> any()`


<a name="start_link-0"></a>

### start_link/0 ###

`start_link() -> any()`


