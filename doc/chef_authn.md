

# Module chef_authn #
* [Description](#description)
* [Data Types](#types)
* [Function Index](#index)
* [Function Details](#functions)


chef_authn - Request signing and authentication for Opscode Chef.
__Authors:__ Seth Falcon ([`seth@opscode.com`](mailto:seth@opscode.com)), Christopher Brown ([`cb@opscode.com`](mailto:cb@opscode.com)).
<a name="description"></a>

## Description ##



This module is an Erlang port of the mixlib-authentication Ruby gem.
It can be used to sign HTTP requests to send to a Chef server or to
validate such requests (for server implementation).



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

<a name="types"></a>

## Data Types ##




### <a name="type-base64_binary">base64_binary()</a> ###



<pre><code>
base64_binary() = &lt;&lt;_:64, _:_*8&gt;&gt;
</code></pre>





### <a name="type-get_header_fun">get_header_fun()</a> ###



<pre><code>
get_header_fun() = fun((<a href="#type-header_name">header_name()</a>) -&gt; <a href="#type-header_value">header_value()</a>)
</code></pre>





### <a name="type-header_fun">header_fun()</a> ###



<pre><code>
header_fun() = fun((<a href="#type-header_name">header_name()</a>) -&gt; <a href="#type-header_value">header_value()</a>)
</code></pre>



  -type rsa_public_key() :: public_key:rsa_public_key().



### <a name="type-header_name">header_name()</a> ###



<pre><code>
header_name() = binary()
</code></pre>





### <a name="type-header_value">header_value()</a> ###



<pre><code>
header_value() = binary() | undefined
</code></pre>





### <a name="type-http_body">http_body()</a> ###



<pre><code>
http_body() = binary() | pid()
</code></pre>





### <a name="type-http_method">http_method()</a> ###



<pre><code>
http_method() = binary()
</code></pre>





### <a name="type-http_path">http_path()</a> ###



<pre><code>
http_path() = binary()
</code></pre>





### <a name="type-public_key_data">public_key_data()</a> ###



<pre><code>
public_key_data() = {cert, <a href="#type-base64_binary">base64_binary()</a>} | {key, <a href="#type-base64_binary">base64_binary()</a>} | <a href="#type-base64_binary">base64_binary()</a>
</code></pre>





### <a name="type-sha_hash64">sha_hash64()</a> ###



<pre><code>
sha_hash64() = binary()
</code></pre>





### <a name="type-signing_algorithm">signing_algorithm()</a> ###



<pre><code>
signing_algorithm() = &lt;&lt;_:32&gt;&gt;
</code></pre>





### <a name="type-signing_version">signing_version()</a> ###



<pre><code>
signing_version() = &lt;&lt;_:24&gt;&gt;
</code></pre>





### <a name="type-user_id">user_id()</a> ###



<pre><code>
user_id() = binary()
</code></pre>


<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#accepted_signing_algorithm-1">accepted_signing_algorithm/1</a></td><td>Is the signing algorithm valid?
of {unknown_algorithm, Algorithm}.</td></tr><tr><td valign="top"><a href="#accepted_signing_version-1">accepted_signing_version/1</a></td><td>Is the signing version acceptable for chef request.</td></tr><tr><td valign="top"><a href="#authenticate_user_request-6">authenticate_user_request/6</a></td><td>Determine if a request is valid.</td></tr><tr><td valign="top"><a href="#default_signing_algorithm-0">default_signing_algorithm/0</a></td><td>Return the default signing algorithm.</td></tr><tr><td valign="top"><a href="#default_signing_version-0">default_signing_version/0</a></td><td>Return the default signing version.</td></tr><tr><td valign="top"><a href="#extract_private_key-1">extract_private_key/1</a></td><td></td></tr><tr><td valign="top"><a href="#extract_public_key-1">extract_public_key/1</a></td><td></td></tr><tr><td valign="top"><a href="#extract_public_or_private_key-1">extract_public_or_private_key/1</a></td><td>Given PEM content as binary, return either an RSA public or private key record (or
error tuple).</td></tr><tr><td valign="top"><a href="#hash_file-1">hash_file/1</a></td><td>Base 64 encoded SHA1 of contents of <code>F</code>, which must be the pid of a file.</td></tr><tr><td valign="top"><a href="#hash_string-1">hash_string/1</a></td><td>Base 64 encoded SHA1 of <code>Str</code></td></tr><tr><td valign="top"><a href="#sign_request-5">sign_request/5</a></td><td>Sign an HTTP request without a body (primarily GET).</td></tr><tr><td valign="top"><a href="#sign_request-6">sign_request/6</a></td><td></td></tr><tr><td valign="top"><a href="#sign_request-8">sign_request/8</a></td><td>Sign an HTTP request so it can be sent to a Chef server.</td></tr><tr><td valign="top"><a href="#validate_headers-2">validate_headers/2</a></td><td>Validate that all required headers are present.</td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="accepted_signing_algorithm-1"></a>

### accepted_signing_algorithm/1 ###


<pre><code>
accepted_signing_algorithm(Algorithm::binary()) -&gt; boolean()
</code></pre>

<br></br>


Is the signing algorithm valid?
of {unknown_algorithm, Algorithm}
<a name="accepted_signing_version-1"></a>

### accepted_signing_version/1 ###


<pre><code>
accepted_signing_version(Version::binary()) -&gt; boolean()
</code></pre>

<br></br>


Is the signing version acceptable for chef request.  Returns true if so, else false.
<a name="authenticate_user_request-6"></a>

### authenticate_user_request/6 ###


<pre><code>
authenticate_user_request(GetHeader::<a href="#type-get_header_fun">get_header_fun()</a>, Method::<a href="#type-http_method">http_method()</a>, Path::<a href="#type-http_path">http_path()</a>, Body::<a href="#type-http_body">http_body()</a>, PublicKey::<a href="#type-public_key_data">public_key_data()</a> | <a href="#type-rsa_public_key">rsa_public_key()</a>, TimeSkew::<a href="#type-time_skew">time_skew()</a>) -&gt; {name, <a href="#type-user_id">user_id()</a>} | {no_authn, Reason::term()}
</code></pre>

<br></br>



Determine if a request is valid



The `GetHeader` argument is a fun that closes over the request
headers and can be called to obtain the value of a header.  It
should either return the value of the header as binary or
'undefined'.



A request signed with a timestamp more than `TimeSkew` seconds from
now will not be authenticated.


`PublicKey` is a binary containing an RSA public key in PEM format.

<a name="default_signing_algorithm-0"></a>

### default_signing_algorithm/0 ###


<pre><code>
default_signing_algorithm() -&gt; <a href="#type-signing_algorithm">signing_algorithm()</a>
</code></pre>

<br></br>


Return the default signing algorithm
<a name="default_signing_version-0"></a>

### default_signing_version/0 ###


<pre><code>
default_signing_version() -&gt; <a href="#type-signing_version">signing_version()</a>
</code></pre>

<br></br>


Return the default signing version
<a name="extract_private_key-1"></a>

### extract_private_key/1 ###


<pre><code>
extract_private_key(RawKey::binary()) -&gt; #'RSAPrivateKey'{} | {error, bad_key}
</code></pre>

<br></br>



<a name="extract_public_key-1"></a>

### extract_public_key/1 ###


<pre><code>
extract_public_key(RawKey::binary()) -&gt; #'RSAPublicKey'{} | {error, bad_key}
</code></pre>

<br></br>



<a name="extract_public_or_private_key-1"></a>

### extract_public_or_private_key/1 ###


<pre><code>
extract_public_or_private_key(RawKey::binary()) -&gt; #'RSAPublicKey'{} | #'RSAPrivateKey'{} | {error, bad_key}
</code></pre>

<br></br>


Given PEM content as binary, return either an RSA public or private key record (or
error tuple). The PEM can contain an RSA public key in PKCS1, SPKI (X509), or an X509
certificate wrapping an SPKI formatted key. Note that private keys will not be extracted
from X509 certificate data.
<a name="hash_file-1"></a>

### hash_file/1 ###


<pre><code>
hash_file(F::pid()) -&gt; <a href="#type-sha_hash64">sha_hash64()</a>
</code></pre>

<br></br>


Base 64 encoded SHA1 of contents of `F`, which must be the pid of a file
<a name="hash_string-1"></a>

### hash_string/1 ###


<pre><code>
hash_string(Str::string() | binary()) -&gt; <a href="#type-sha_hash64">sha_hash64()</a>
</code></pre>

<br></br>


Base 64 encoded SHA1 of `Str`
<a name="sign_request-5"></a>

### sign_request/5 ###


<pre><code>
sign_request(PrivateKey::<a href="#type-rsa_private_key">rsa_private_key()</a>, User::<a href="#type-user_id">user_id()</a>, Method::<a href="#type-http_method">http_method()</a>, Time::<a href="#type-erlang_time">erlang_time()</a> | now, Path::<a href="#type-http_path">http_path()</a>) -&gt; [{[any()], [any()]}]
</code></pre>

<br></br>


Sign an HTTP request without a body (primarily GET)
<a name="sign_request-6"></a>

### sign_request/6 ###


<pre><code>
sign_request(PrivateKey::<a href="#type-rsa_private_key">rsa_private_key()</a>, Body::<a href="#type-http_body">http_body()</a>, User::<a href="#type-user_id">user_id()</a>, Method::<a href="#type-http_method">http_method()</a>, Time::<a href="#type-erlang_time">erlang_time()</a> | now, Path::<a href="#type-http_path">http_path()</a>) -&gt; [{[any()], [any()]}]
</code></pre>

<br></br>



<a name="sign_request-8"></a>

### sign_request/8 ###


<pre><code>
sign_request(PrivateKey::<a href="#type-rsa_private_key">rsa_private_key()</a>, Body::<a href="#type-http_body">http_body()</a>, User::<a href="#type-user_id">user_id()</a>, Method::<a href="#type-http_method">http_method()</a>, Time::<a href="#type-erlang_time">erlang_time()</a> | now, Path::<a href="#type-http_path">http_path()</a>, SignAlgorithm::<a href="#type-signing_algorithm">signing_algorithm()</a>, SignVersion::<a href="#type-signing_version">signing_version()</a>) -&gt; [{[any()], [any()]}]
</code></pre>

<br></br>



Sign an HTTP request so it can be sent to a Chef server.



Returns a list of header tuples that should be included in the
final HTTP request.



The keys are returned as strings to match with what is required by ibrowse. The values
are returned as binary().


Note that the headers can't be passed directly to validate_headers which expects headers to
have binary keys (as returned from the ejson/jiffy parsing routines
<a name="validate_headers-2"></a>

### validate_headers/2 ###


<pre><code>
validate_headers(GetHeader::<a href="#type-header_fun">header_fun()</a>, TimeSkew::<a href="#type-time_skew">time_skew()</a>) -&gt; [{algorithm, binary()} | {version, binary()}, ...]
</code></pre>

<br></br>


throws `{missing, [binary()]} | bad_clock | bad_sign_desc`



Validate that all required headers are present


Returns 'ok' if all required headers are present.  Otherwise, throws
`{missing, [header_name()]}` providing a list of the
missing headers in the exception.

