# TRIAD reproducibility targets. All project execution is Ubuntu 22.04/24.04
# only; these targets fail fast on macOS and other unsupported systems.
PYTHON ?= python3

.PHONY: doctor test validate run-example export clean

doctor:
	$(PYTHON) -m triad doctor

test:
	$(PYTHON) -m unittest discover -s tests -v

validate:
	bash scripts/validate-ubuntu.sh

run-example:
	$(PYTHON) -m triad run-example

export:
	$(PYTHON) -m triad export --output dist/TRIAD-artifact-support.tar.gz

clean:
	rm -rf dist results .venv
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
