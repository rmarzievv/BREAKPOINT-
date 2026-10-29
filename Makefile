PY ?= python3
export PYTHONPATH := $(CURDIR)

.PHONY: all setup fetch pilot dcc test

all: fetch pilot dcc test

setup:
	git submodule update --init --recursive
	$(PY) -m pip install -r requirements.txt

fetch:            ## external inputs at pinned commits -> ext/
	./scripts/fetch_external.sh

pilot:            ## data/pilot_implementations.csv
	$(PY) scripts/build_pilot_list.py

dcc:              ## data/pilot_rules.csv, data/dcc_claims.csv, data/manual_baseline.csv
	$(PY) scripts/run_dcc.py

test:
	$(PY) -m pytest -q
