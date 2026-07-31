PYTHON ?= .venv/bin/python

.PHONY: setup test package-check forward-check whitespace-check validate build verify-dist clean

setup:
	./setup.sh

test:
	$(PYTHON) -m pytest -q

package-check:
	$(PYTHON) scripts/validate_package.py --root . --format text

forward-check:
	$(PYTHON) -m pytest -q tests/test_forward_results.py

whitespace-check:
	$(PYTHON) scripts/check_whitespace.py

validate: test package-check forward-check whitespace-check

build:
	$(PYTHON) scripts/build_release.py

verify-dist:
	$(PYTHON) scripts/build_release.py --verify

clean:
	rm -rf dist build
