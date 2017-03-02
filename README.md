# Chef Authentication

This is an erlang library for authenticating HTTP requests made using
Chef's header signing protocol. See Chef RFC 065 for more details:

    https://github.com/chef/chef-rfc/blob/master/rfc065-sign-v1.3.md

Additionally, it contains other useful libraries for generating and
managing keys.

## Contributing

For information on contributing to this project
see <https://github.com/chef/chef/blob/master/CONTRIBUTING.md>

## Development

This project uses eunit and dialyzer for testing and
type-checking. You can run both locally with:

    make travis

## License

- Copyright:: 2011-2017 Chef Software, Inc.
- License:: Apache License, Version 2.0

```text
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
