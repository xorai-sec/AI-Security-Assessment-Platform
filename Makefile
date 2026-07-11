.PHONY: install install-frameworks lint typecheck test test-unit test-integration test-e2e security-check build up up-full up-frameworks up-gpu down migrate seed demo-up demo-seed demo-assess demo-report validate validate-targets validate-adapters validate-gpu framework-health target-health register-enterprise-assist register-ollama-target register-vllm-target register-openai-fixture register-custom-rest-fixture assess-target assess-target-group retest-finding generate-reports generate-evidence-package clean

PYTHON ?= python

install:
	$(PYTHON) -m pip install -r apps/api/requirements.txt -r apps/enterprise-assist/requirements.txt -r requirements-dev.txt

install-frameworks:
	@echo "Framework adapters are isolated behind the target abstraction. Install garak/PyRIT/Promptfoo/DeepTeam in dedicated environments before enabling framework workers."

lint:
	$(PYTHON) -m ruff check apps packages scripts tests

typecheck:
	$(PYTHON) -m mypy packages apps/api/app apps/enterprise-assist/app

test:
	$(PYTHON) -m pytest tests/unit

test-unit:
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

up-full:
	docker compose -f docker-compose.yml -f docker-compose.full.yml up --build

up-frameworks:
	docker compose -f docker-compose.yml -f docker-compose.frameworks.yml up --build

up-gpu:
	docker compose -f docker-compose.yml -f docker-compose.gpu.yml up --build

down:
	docker compose down

migrate:
	@echo "Alembic migrations are planned; current Phase 3 build uses file-backed persistence."

seed:
	$(PYTHON) scripts/demo/seed_demo.py

demo-up:
	docker compose up --build -d

demo-seed:
	$(PYTHON) scripts/demo/seed_demo.py

demo-assess:
	$(PYTHON) scripts/demo/run_demo_assessment.py

demo-report:
	$(PYTHON) scripts/demo/show_latest_report.py

validate: lint typecheck test security-check

validate-targets:
	$(PYTHON) scripts/targets/validate_targets.py

validate-adapters:
	$(PYTHON) -m pytest tests/unit/test_target_security.py tests/unit/test_target_adapters.py

framework-health:
	$(PYTHON) -c "import httpx; print(httpx.get('http://127.0.0.1:8080/api/adapters/health', timeout=10).json())"

target-health:
	$(PYTHON) scripts/targets/validate_targets.py

register-enterprise-assist:
	$(PYTHON) scripts/targets/register_enterprise_assist.py

register-openai-fixture:
	$(PYTHON) scripts/targets/register_openai_fixture.py

register-custom-rest-fixture:
	$(PYTHON) scripts/targets/register_custom_rest_fixture.py

register-ollama-target:
	@echo "Set OLLAMA_URL and register through the UI or API. Ollama adapter is implemented; automated registration is environment-specific."

register-vllm-target:
	@echo "Set VLLM_URL and register through the UI or API. vLLM uses the OpenAI-compatible adapter."

assess-target:
	$(PYTHON) scripts/targets/assess_target.py

assess-target-group:
	$(PYTHON) scripts/targets/compare_targets.py

retest-finding:
	@echo "Retest workflow is documented but not fully automated in this build."; exit 1

generate-reports:
	$(PYTHON) scripts/demo/show_latest_report.py

generate-evidence-package:
	@echo "Evidence package export is planned after PostgreSQL/object storage wiring."; exit 1

validate-gpu:
	bash scripts/gpu/check_nvidia.sh
	bash scripts/gpu/check_docker_gpu.sh

clean:
	rm -rf data/evidence data/reports .pytest_cache .mypy_cache .ruff_cache
