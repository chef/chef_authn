all: compile eunit dialyzer

clean:
	@rebar clean

distclean: clean
	@rm -rf deps

compile:
	@rebar compile

dialyzer:
	@dialyzer -Wrace_conditions -Wunderspecs -r ebin

eunit: compile
	@rebar skip_deps=true eunit

test: eunit
