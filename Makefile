REBAR = $(CURDIR)/rebar3

travis:
	$(REBAR) do eunit, dialyzer

all: travis
