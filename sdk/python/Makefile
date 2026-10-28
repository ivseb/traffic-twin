# Local shortcuts (python >= 3.9). PYTHONPATH=src:. runs the sources without installing.
PY ?= python3
export PYTHONPATH := src:.

.PHONY: vectors test bench
vectors:
	$(PY) -m traffic_twin.conformance
test:
	$(PY) -m unittest discover -s tests -t .
bench:
	$(PY) bench/overhead.py
