# Phase 4 Test Results

## Local Windows checks

| Check | Result |
|---|---|
| Python compile check for API, framework manager and workers | Passed |
| Frontend TypeScript/Vite build | Passed |

## Ubuntu validation commands

```bash
git pull
cp .env.example .env
sudo docker compose -f docker-compose.yml -f docker-compose.frameworks.yml up --build -d
source .venv/bin/activate
make install
make migrate
make register-enterprise-assist
make framework-health
make framework-self-test
make assess-all
make generate-pdf-reports
make generate-evidence-package
```

Observed Ubuntu results must be added after execution.

