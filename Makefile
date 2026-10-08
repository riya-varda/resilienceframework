.PHONY: all test demo sweep plots reproduce clean help

PYTHON ?= python

help:
	@echo "IRTI - Forensic Resilience Framework"
	@echo "Targets:"
	@echo "  make test        - Run all 9 self-tests"
	@echo "  make demo        - Run 5-minute interactive incident demo"
	@echo "  make sweep       - Run seed x condition experiment sweep"
	@echo "  make plots       - Generate figures from results.csv"
	@echo "  make reproduce   - Full end-to-end reproduction (test -> sweep -> plots)"
	@echo "  make clean       - Remove generated run logs and cache"

test:
	$(PYTHON) irti/selftest.py -v

demo:
	$(PYTHON) irti/demo.py

sweep:
	$(PYTHON) irti/run.py --seeds 0 1 2 3 4 --n 500 --random-losses 10 25 50 75 90

plots:
	$(PYTHON) irti/plots.py

reproduce:
	$(PYTHON) irti/reproduce.py

clean:
	@rm -rf irti/__pycache__ irti/vectors/__pycache__ irti/runs
