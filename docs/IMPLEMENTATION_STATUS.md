# Implementation Status

> Historical status document. DeepTeam references below are superseded and
> are not part of the active product.

## Capability Status

| Capability | Status | Notes |
|---|---|---|
| Repository foundation | Complete and tested | Metadata, docs, Docker/Make structure created |
| EnterpriseAssist target | Complete but not fully tested | Vulnerable/hardened modes with synthetic data |
| Native controlled campaigns | Complete but not fully tested | Six deterministic vulnerability checks |
| Evidence capture | Complete but not fully tested | JSON/Markdown/HTML/CSV outputs |
| Risk scoring | Complete but not fully tested | Transparent scoring model |
| ISO mapping | Complete but not fully tested | Original placeholder mapping, no copyrighted ISO text |
| Frontend | Partially implemented | Demo dashboard, not full enterprise workflow |
| PostgreSQL persistence | Planned | Compose includes service; app uses local evidence store first |
| Redis queue | Planned | Compose includes service; worker planned |
| garak adapter | Planned | Adapter contract exists; execution not implemented in this repo yet |
| PyRIT adapter | Planned | Objective model documented |
| Promptfoo adapter | Planned | Regression-export planned |
| DeepTeam adapter | Planned | Comparative validation planned |
| GPU support | Partially implemented | Scripts/docs for NVIDIA and CPU/AMD fallback |

## Known Limitations

- First release is a controlled proof-of-capability, not an ISO certification tool.
- No licensed ISO text is included.
- Framework adapters are represented by health interfaces and roadmap status until implemented.
- Full authentication and RBAC are not complete in the first release.
- Docker Compose starts PostgreSQL/Redis, but the first working demo stores evidence locally.
