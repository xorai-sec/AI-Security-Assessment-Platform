# 15-20 Minute Demo Script

## 1. Explain the Problem

Organizations adopting AI need evidence that technical AI risks are understood,
tested, remediated, and monitored. ISO/IEC 42001 asks for an AI management system;
this platform connects technical adversarial testing to evidence candidates.

## 2. Show the Architecture

Open `README.md` and show the Mermaid architecture. Emphasize that the first demo
uses a controlled synthetic target.

## 3. Start the Platform

```bash
make demo-up
```

Open:

```text
http://localhost:5173
```

## 4. Seed Demo Context

```bash
make demo-seed
```

Explain the organization profile and EnterpriseAssist AI system.

## 5. Run Vulnerable Assessment

```bash
make demo-assess
```

This runs vulnerable and hardened assessments. Vulnerable mode should produce
controlled findings. Hardened mode should reduce or remove them.

## 6. Show Evidence

Open `data/evidence/` and explain:

- prompt sent
- response received
- retrieval trace
- tool trace
- authorization trace
- evaluator result
- evidence hash

## 7. Show Findings

Open the web UI or API:

```text
http://localhost:8080/api/assessments
```

Explain severity, confidence, reproducibility, and remediation.

## 8. Show ISO Mapping

Open a generated report in `data/reports/`.

Explain:

- technical observation
- AI risk
- control objective
- available evidence
- missing organizational evidence
- human-review requirement

## 9. Explain Limitations

State clearly:

- no ISO certification claim
- framework adapters are roadmap unless enabled
- synthetic data only
- production evidence storage requires hardening

## 10. Close

Position the platform as a proof-of-capability showing how technical AI red-team
results can become repeatable assurance evidence.

