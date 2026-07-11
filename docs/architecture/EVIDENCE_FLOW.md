# Evidence Flow

```mermaid
flowchart TD
    Prompt["Prompt"] --> Adapter["Target adapter"]
    Adapter --> Response["Response and telemetry"]
    Response --> Sanitize["Sanitize and mask"]
    Sanitize --> Hash["Evidence hash"]
    Hash --> Finding["Finding correlation"]
    Finding --> ISO["ISO/IEC 42001 candidate mapping"]
    ISO --> Report["Reports"]
```

Black-box targets record prompt, response, timing and token usage where available. Grey-box and white-box targets may include retrieval, tool, authorization, memory and security-event telemetry.

