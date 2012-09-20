all: compile eunit dialyzer

clean:
	@rebar clean

distclean: clean

compile:
	@rebar compile

dialyzer:
	@dialyzer -Wrace_conditions -Wunderspecs -r ebin

eunit: compile
	@rebar skip_deps=true eunit

test: eunit

doc:
	@rebar doc skip_deps=true

.PHONY: all clean distclean compile dialyzer eunit test doc
