.PHONY: install lint typecheck test test-integration test-e2e security-check build up down demo-up demo-seed demo-assess demo-report validate validate-gpu clean

PYTHON ?= python

install:
	$(PYTHON) -m pip install -r apps/api/requirements.txt -r apps/enterprise-assist/requirements.txt -r requirements-dev.txt

lint:
	$(PYTHON) -m ruff check apps packages scripts tests

typecheck:
	$(PYTHON) -m mypy packages apps/api/app apps/enterprise-assist/app

test:
	$(PYTHON) -m pytest tests/unit

test-integration:
	$(PYTHON) -m pytest tests/integration

test-e2e:
	$(PYTHON) -m pytest tests/e2e

security-check:
	$(PYTHON) scripts/validation/secret_scan.py

build:
	docker compose build

up:
	docker compose up --build

down:
	docker compose down

demo-up:
	docker compose up --build -d

demo-seed:
	$(PYTHON) scripts/demo/seed_demo.py

demo-assess:
	$(PYTHON) scripts/demo/run_demo_assessment.py

demo-report:
	$(PYTHON) scripts/demo/show_latest_report.py

validate: lint typecheck test security-check

validate-gpu:
	bash scripts/gpu/check_nvidia.sh
	bash scripts/gpu/check_docker_gpu.sh

clean:
	rm -rf data/evidence data/reports .pytest_cache .mypy_cache .ruff_cache

