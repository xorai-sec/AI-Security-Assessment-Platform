# Credential Handling

Credentials are separated from general configuration and masked in API responses. Development encryption uses `AISEC_CREDENTIAL_KEY`.

Do not use the development protector for production secrets. Replace it with a managed secret store or KMS-backed encryption before client assessment.

