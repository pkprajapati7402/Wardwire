.PHONY: init up down demo test lint typecheck eval bench scan sbom clean help

PYTHON ?= python
VENV_PYTHON = .venv/bin/python
ifeq ($(OS),Windows_NT)
    VENV_PYTHON = .venv/Scripts/python.exe
endif

help:
	@echo "Wardwire Commands:"
	@echo "  make init       Generate .env with cryptographically secure secrets"
	@echo "  make up         Start all services via Docker Compose"
	@echo "  make down       Stop all services"
	@echo "  make demo       Start services, seed initial replay dataset, open dashboard"
	@echo "  make test       Run all unit, integration, and security tests"
	@echo "  make lint       Run ruff linter and code formatting checks"
	@echo "  make typecheck  Run mypy type checker"
	@echo "  make eval       Run deterministic evaluation harness across all attack families"
	@echo "  make bench      Run performance and latency benchmarks"
	@echo "  make scan       Run security scans (pip-audit, bandit)"
	@echo "  make sbom       Generate CycloneDX SBOM report"
	@echo "  make clean      Remove build artifacts, caches, and test artifacts"

init:
	$(PYTHON) scripts/init_env.py

up:
	docker compose --profile lab up -d

down:
	docker compose --profile lab down

demo:
	docker compose --profile lab up -d
	@echo "Waiting for services to become healthy..."
	$(PYTHON) scripts/wait_and_seed.py

test:
	$(PYTHON) -m pytest tests/ -v --durations=10

lint:
	$(PYTHON) -m ruff check src/ tests/

typecheck:
	$(PYTHON) -m mypy src/sentinel/core

eval:
	$(PYTHON) -m sentinel.eval.harness --seed 42 --output reports/

bench:
	$(PYTHON) -m sentinel.eval.benchmark --events 5000 --output reports/bench.json

scan:
	$(PYTHON) -m pip_audit
	$(PYTHON) -m bandit -r src/ -ll

sbom:
	$(PYTHON) -m cyclonedx_py environment -o reports/sbom.json

clean:
	rm -rf .pytest_cache .coverage htmlcov dist build *.egg-info reports/*.tmp

