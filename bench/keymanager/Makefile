# This makefile is currently intended to make it easy to generate the
# benchmarking graphs.

RESULTS_FILE = tests/results.json
GRAPH_PREFIX = benchmark

GRAPH_FILE = $(GRAPH_PREFIX)-test_gpg_init.svg

all: $(GRAPH_FILE)

#
# rules for generating one graph with the results of all speed tests
#

$(RESULTS_FILE):
	tox -v test_gpg_speed.py -- -v --pdb -s \
	    --benchmark-max-time=2.0 \
	    --benchmark-json=$(subst tests/,,$@)

$(GRAPH_FILE): $(RESULTS_FILE)
	py.test-benchmark compare $< --histogram $(GRAPH_PREFIX)


#
# rule for generating one graph for each graph
#

test:
	tox -v test_gpg_speed.py -- -v --pdb -s \
	    --benchmark-histogram=gpg_speed \
	    --benchmark-storage=./graphs/ \
	    --benchmark-save=keymanager_gpg_speed \

clean:
	rm -f $(RESULTS_FILE) $(GRAPH_PREFIX)*.svg

.PHONY: all test graph
