# SSRF Protection

The platform validates target URLs before assessment:

- HTTP/HTTPS only.
- File and socket schemes are rejected.
- Cloud metadata IPs are blocked.
- Link-local, multicast and unspecified addresses are blocked.
- Local and private addresses require administrator policy.
- Ports must be in an allowlist.

Environment controls:

```bash
AISEC_ALLOW_LOCAL_TARGETS=true
AISEC_ALLOW_PRIVATE_TARGETS=false
AISEC_ALLOWED_TARGET_PORTS=80,443,8000,8001,8080,8090,11434
AISEC_ALLOWED_LOCAL_HOSTS=127.0.0.1,localhost,enterprise-assist,ollama,vllm
```

