# Phase 3 Security Review

## Implemented controls

- URL scheme allowlist: HTTP and HTTPS only.
- Port allowlist with administrator environment override.
- Local laboratory host allowlist.
- Blocking for cloud metadata, link-local, multicast, unspecified, and private destinations when not approved.
- Credential masking in API responses.
- Development credential protection using `AISEC_CREDENTIAL_KEY`.
- Authorization and kill-switch acknowledgement required before assessment.
- Production targets blocked by default through `AssessmentScope`.
- No arbitrary Python or shell mapping support.
- Custom REST mappings use field paths only.

## Remaining security work

- Replace development credential protector with KMS/Vault or database encryption.
- Add redirect destination revalidation during HTTP client execution.
- Add DNS rebinding regression tests with controlled resolver fixtures.
- Add role-based API access control and credential audit events.
- Add global kill-switch API and worker cancellation once Redis workers are wired.

