

# Module chef_time_utils #
* [Description](#description)
* [Function Index](#index)
* [Function Details](#functions)


chef_time_utils - helpers for converting between http and erlang time.
Copyright (c) 2011-2012 Opscode, Inc. All Rights Reserved.

__Authors:__ Seth Falcon ([`seth@opscode.com`](mailto:seth@opscode.com)), Christopher Brown ([`cb@opscode.com`](mailto:cb@opscode.com)).
<a name="description"></a>

## Description ##



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
<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#canonical_time-1">canonical_time/1</a></td><td>Convert a string or binary HTTP request time to iso8601 format.</td></tr><tr><td valign="top"><a href="#time_in_bounds-2">time_in_bounds/2</a></td><td>Check if a time, expressed as an ISO8601 string is equal to the current time, within
a given Skew interval.</td></tr><tr><td valign="top"><a href="#time_in_bounds-3">time_in_bounds/3</a></td><td>Check if two times are equal within a given Skew interval.</td></tr><tr><td valign="top"><a href="#time_iso8601-1">time_iso8601/1</a></td><td>Converts Erlang time-tuple to iso8601 formatted date string.</td></tr><tr><td valign="top"><a href="#time_iso8601_to_date_time-1">time_iso8601_to_date_time/1</a></td><td>Convert an iso8601 time string to Erlang date time
representation.</td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="canonical_time-1"></a>

### canonical_time/1 ###


<pre><code>
canonical_time(T::string() | binary()) -&gt; <a href="#type-iso8601_time">iso8601_time()</a>
</code></pre>

<br></br>


Convert a string or binary HTTP request time to iso8601 format
<a name="time_in_bounds-2"></a>

### time_in_bounds/2 ###


<pre><code>
time_in_bounds(ReqTime::undefined | string() | binary(), Skew::<a href="#type-time_skew">time_skew()</a>) -&gt; boolean() | invalid_reqtime
</code></pre>

<br></br>



Check if a time, expressed as an ISO8601 string is equal to the current time, within
a given Skew interval.


Returns invalid_reqtime if the ISO8601 time can't be parsed
<a name="time_in_bounds-3"></a>

### time_in_bounds/3 ###


<pre><code>
time_in_bounds(T1::<a href="#type-erlang_time">erlang_time()</a>, T2::<a href="#type-erlang_time">erlang_time()</a>, Skew::<a href="#type-time_skew">time_skew()</a>) -&gt; boolean()
</code></pre>

<br></br>


Check if two times are equal within a given Skew interval.

<a name="time_iso8601-1"></a>

### time_iso8601/1 ###


<pre><code>
time_iso8601(X1::<a href="#type-erlang_time">erlang_time()</a> | now) -&gt; binary()
</code></pre>

<br></br>



Converts Erlang time-tuple to iso8601 formatted date string.


Example output looks like `<<"2003-12-13T18:30:02Z">>`
<a name="time_iso8601_to_date_time-1"></a>

### time_iso8601_to_date_time/1 ###


<pre><code>
time_iso8601_to_date_time(ATime::string() | binary()) -&gt; <a href="#type-erlang_time">erlang_time()</a>
</code></pre>

<br></br>


Convert an iso8601 time string to Erlang date time
representation.
