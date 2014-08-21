# NOTE: this target appears to be broken but the cause seems to be
# rebar based. Setting any macro on the command line is giving
# errors about redefining the macro.
slow_test:
	touch test/chef_keygen_cache_tests.erl
	rebar eunit skip_deps=true -DSLOW_TESTS

# if we don't reset the default goal, then slow_test above will be it
# because at present custom.mk is included first.
.DEFAULT_GOAL :=
