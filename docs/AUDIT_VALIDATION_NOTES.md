# Validation Notes

Validation date: 2026-07-19

## Completed

- `git status --short --branch` — repository is on `main` with pre-existing modified and untracked work; nothing was discarded.
- `docker compose config` — passed.
- `docker compose -f docker-compose.yml -f docker-compose.frameworks.yml config` — passed.
- `python scripts/validation/secret_scan.py` — passed.
- `conda run -n jais310 python -m pytest -q` — passed (22 tests) after adding
  Python 3.10-compatible UTC handling.
- `conda run -n jais310 python -m ruff check apps packages scripts tests` — passed.
- `conda run -n jais310 python -m mypy packages apps/api/app apps/enterprise-assist/app` — passed.

## Blocked

- `make install` — blocked because this environment could not resolve `pypi.org`; pip could not download `fastapi==0.116.1`.
- Root `make validate` — not rerun end-to-end in this environment; run it from the
  activated environment after dependency installation.
- Docker service startup, image builds, health checks, demo seed, vulnerable/hardened assessments, and clean shutdown — blocked because the current execution environment cannot access `/var/run/docker.sock`.
- GitHub Actions execution — not run locally; use the hosted workflow after dependencies and Docker are available.

## Commands to run when access is available

```bash
make install
make validate
docker compose build
docker compose up -d
make demo-seed
make demo-assess
make hardened-retest
make demo-report
docker compose down
```

Expected successful outcome: lint, type checking, tests, Compose build/start, service health checks, demo evidence, and reports all pass; the hardened retest produces fewer successful attacks than the vulnerable target.

No enterprise-readiness claim should be made until these blocked checks pass on a host with network access and Docker permissions.
