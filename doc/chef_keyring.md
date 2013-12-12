

# Module chef_keyring #
* [Function Index](#index)
* [Function Details](#functions)

__Version:__ 0.0.2
Copyright 2011-2012 Opscode, Inc. All Rights Reserved.

This file is provided to you under the Apache License,
Version 2.0 (the "License"); you may not use this file
except in compliance with the License.  You may obtain
a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.


__Behaviours:__ [`gen_server`](gen_server.md).

__Authors:__ Kevin Smith ([`kevin@opscode.com`](mailto:kevin@opscode.com)), Mark Anderson ([`mark@opscode.com`](mailto:mark@opscode.com)).
<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#code_change-3">code_change/3</a></td><td></td></tr><tr><td valign="top"><a href="#get_key-1">get_key/1</a></td><td></td></tr><tr><td valign="top"><a href="#handle_call-3">handle_call/3</a></td><td></td></tr><tr><td valign="top"><a href="#handle_cast-2">handle_cast/2</a></td><td></td></tr><tr><td valign="top"><a href="#handle_info-2">handle_info/2</a></td><td></td></tr><tr><td valign="top"><a href="#init-1">init/1</a></td><td></td></tr><tr><td valign="top"><a href="#list_keys-0">list_keys/0</a></td><td></td></tr><tr><td valign="top"><a href="#reload-0">reload/0</a></td><td></td></tr><tr><td valign="top"><a href="#reload_if_changed-0">reload_if_changed/0</a></td><td></td></tr><tr><td valign="top"><a href="#start_link-0">start_link/0</a></td><td></td></tr><tr><td valign="top"><a href="#stats-0">stats/0</a></td><td></td></tr><tr><td valign="top"><a href="#terminate-2">terminate/2</a></td><td></td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="code_change-3"></a>

### code_change/3 ###

`code_change(OldVsn, State, Extra) -> any()`


<a name="get_key-1"></a>

### get_key/1 ###

`get_key(KeyName) -> any()`


<a name="handle_call-3"></a>

### handle_call/3 ###

`handle_call(Request, From, State) -> any()`


<a name="handle_cast-2"></a>

### handle_cast/2 ###

`handle_cast(Request, State) -> any()`


<a name="handle_info-2"></a>

### handle_info/2 ###

`handle_info(Info, State) -> any()`


<a name="init-1"></a>

### init/1 ###

`init(X1) -> any()`


<a name="list_keys-0"></a>

### list_keys/0 ###

`list_keys() -> any()`


<a name="reload-0"></a>

### reload/0 ###

`reload() -> any()`


<a name="reload_if_changed-0"></a>

### reload_if_changed/0 ###

`reload_if_changed() -> any()`


<a name="start_link-0"></a>

### start_link/0 ###

`start_link() -> any()`


<a name="stats-0"></a>

### stats/0 ###

`stats() -> any()`


<a name="terminate-2"></a>

### terminate/2 ###

`terminate(Reason, State) -> any()`


