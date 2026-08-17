# Seeded vulnerable demo target.
PYTHON ?= python3

.PHONY: all build test clean run
all: build

build:
	$(PYTHON) -m compileall -q src

test: build
	$(PYTHON) -m pytest tests -q

run:
	$(PYTHON) src/main.py --request '{"op":"ping"}'

clean:
	rm -rf src/**/__pycache__ src/__pycache__ .pytest_cache exports
