.PHONY: install install-frameworks prepare-runtime validate-artifact-permissions setup-ollama-models lint typecheck test test-unit test-integration test-e2e security-check build build-frameworks up up-full up-frameworks up-gpu down migrate seed demo-up demo-seed demo-assess demo-report validate validate-targets validate-adapters validate-frameworks validate-e2e validate-gpu inspect-garak inspect-pyrit inspect-deepteam framework-health framework-self-test self-test-garak self-test-pyrit self-test-promptfoo self-test-deepteam target-health register-enterprise-assist register-ollama-target register-vllm-target register-openai-fixture register-custom-rest-fixture assess-target assess-native assess-garak assess-pyrit assess-promptfoo assess-deepteam assess-all assess-all-quick assess-all-standard assess-all-comprehensive validate-garak-native validate-pyrit-native validate-deepteam-native assess-target-group assess-model-group hardened-retest retest-finding generate-reports generate-pdf-reports generate-evidence-package clean

PYTHON ?= python

install:
	$(PYTHON) -m pip install -r apps/api/requirements.txt -r apps/enterprise-assist/requirements.txt -r requirements-dev.txt

install-frameworks:
	docker compose -f docker-compose.yml -f docker-compose.frameworks.yml build native-worker garak-worker pyrit-worker promptfoo-worker deepteam-worker

prepare-runtime:
	bash scripts/runtime/prepare_runtime.sh

validate-artifact-permissions:
	bash scripts/runtime/validate_artifact_permissions.sh

setup-ollama-models:
	bash scripts/setup_ollama_models.sh

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

build-frameworks:
	docker compose -f docker-compose.yml -f docker-compose.frameworks.yml build

up:
	docker compose up --build

up-full:
	docker compose -f docker-compose.yml -f docker-compose.full.yml up --build

up-frameworks: prepare-runtime
	docker compose -f docker-compose.yml -f docker-compose.frameworks.yml up --build

up-gpu:
	docker compose -f docker-compose.yml -f docker-compose.gpu.yml up --build

down:
	docker compose down

migrate:
	alembic upgrade head

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

inspect-garak:
	bash scripts/frameworks/inspect_garak.sh

inspect-pyrit:
	bash scripts/frameworks/inspect_pyrit.sh

inspect-deepteam:
	bash scripts/frameworks/inspect_deepteam.sh

framework-health:
	$(PYTHON) scripts/frameworks/framework_health.py

framework-self-test:
	$(PYTHON) scripts/frameworks/framework_self_test.py

self-test-garak:
	$(PYTHON) scripts/frameworks/framework_self_test.py garak

self-test-pyrit:
	$(PYTHON) scripts/frameworks/framework_self_test.py pyrit

self-test-promptfoo:
	$(PYTHON) scripts/frameworks/framework_self_test.py promptfoo

self-test-deepteam:
	$(PYTHON) scripts/frameworks/framework_self_test.py deepteam

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

assess-native:
	$(PYTHON) scripts/frameworks/assess_frameworks.py native

assess-garak:
	$(PYTHON) scripts/frameworks/assess_frameworks.py garak

assess-pyrit:
	$(PYTHON) scripts/frameworks/assess_frameworks.py pyrit

assess-promptfoo:
	$(PYTHON) scripts/frameworks/assess_frameworks.py promptfoo

assess-deepteam:
	$(PYTHON) scripts/frameworks/assess_frameworks.py deepteam

assess-all:
	$(PYTHON) scripts/frameworks/assess_frameworks.py native garak pyrit promptfoo deepteam

assess-all-quick:
	PROFILE=quick FRAMEWORK_MAX_REQUESTS=4 FRAMEWORK_MAX_TURNS=3 $(PYTHON) scripts/frameworks/assess_frameworks.py native garak pyrit promptfoo deepteam

assess-all-standard:
	PROFILE=standard FRAMEWORK_MAX_REQUESTS=8 FRAMEWORK_MAX_TURNS=5 $(PYTHON) scripts/frameworks/assess_frameworks.py native garak pyrit promptfoo deepteam

assess-all-comprehensive:
	PROFILE=comprehensive FRAMEWORK_MAX_REQUESTS=14 FRAMEWORK_MAX_TURNS=8 FRAMEWORK_MAX_DURATION_SECONDS=1800 $(PYTHON) scripts/frameworks/assess_frameworks.py native garak pyrit promptfoo deepteam

validate-garak-native:
	TARGET_ID=$(TARGET_ID) PROFILE=$${PROFILE:-quick} FRAMEWORK_MAX_REQUESTS=$${FRAMEWORK_MAX_REQUESTS:-4} FRAMEWORK_MAX_DURATION_SECONDS=$${FRAMEWORK_MAX_DURATION_SECONDS:-900} $(PYTHON) scripts/frameworks/assess_frameworks.py garak

validate-pyrit-native:
	TARGET_ID=$(TARGET_ID) PROFILE=$${PROFILE:-quick} FRAMEWORK_MAX_REQUESTS=$${FRAMEWORK_MAX_REQUESTS:-4} FRAMEWORK_MAX_DURATION_SECONDS=$${FRAMEWORK_MAX_DURATION_SECONDS:-900} $(PYTHON) scripts/frameworks/assess_frameworks.py pyrit

validate-deepteam-native:
	TARGET_ID=$(TARGET_ID) PROFILE=$${PROFILE:-quick} FRAMEWORK_MAX_REQUESTS=$${FRAMEWORK_MAX_REQUESTS:-4} FRAMEWORK_MAX_DURATION_SECONDS=$${FRAMEWORK_MAX_DURATION_SECONDS:-900} $(PYTHON) scripts/frameworks/assess_frameworks.py deepteam

assess-target-group:
	$(PYTHON) scripts/targets/compare_targets.py

assess-model-group:
	$(PYTHON) scripts/targets/compare_targets.py

hardened-retest:
	FRAMEWORKS=native,garak,promptfoo $(PYTHON) scripts/frameworks/assess_frameworks.py

retest-finding:
	@echo "Retest workflow is documented but not fully automated in this build."; exit 1

generate-reports:
	$(PYTHON) scripts/demo/show_latest_report.py

generate-pdf-reports:
	$(PYTHON) scripts/reports/generate_pdf_reports.py

generate-evidence-package:
	$(PYTHON) scripts/reports/generate_evidence_package.py

validate-gpu:
	bash scripts/gpu/check_nvidia.sh
	bash scripts/gpu/check_docker_gpu.sh

validate-frameworks:
	$(PYTHON) scripts/frameworks/framework_health.py
	$(PYTHON) scripts/frameworks/framework_self_test.py

validate-e2e:
	$(PYTHON) scripts/targets/validate_targets.py
	$(PYTHON) scripts/frameworks/assess_frameworks.py native garak pyrit promptfoo deepteam

clean:
	rm -rf data/evidence data/reports .pytest_cache .mypy_cache .ruff_cache
