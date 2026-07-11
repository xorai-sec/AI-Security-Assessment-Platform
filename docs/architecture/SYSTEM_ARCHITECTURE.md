# System Architecture

The first release is a CPU-compatible controlled execution platform.

```mermaid
sequenceDiagram
    participant User
    participant Web
    participant API
    participant Orchestrator
    participant EnterpriseAssist
    participant Evidence

    User->>Web: Launch assessment
    Web->>API: POST /api/assessments/demo
    API->>Orchestrator: Build scope and campaigns
    Orchestrator->>EnterpriseAssist: Send controlled prompts
    EnterpriseAssist-->>Orchestrator: Response + telemetry
    Orchestrator->>Evidence: Store evidence hash and record
    Orchestrator->>API: Findings + ISO mappings
    API-->>Web: Assessment result
```

Future releases will replace local evidence storage with PostgreSQL/object storage
and add Redis-backed workers for long-running framework campaigns.

