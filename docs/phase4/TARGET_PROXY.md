# Target Proxy

Framework workers use `POST /internal/targets/{target_id}/message` with `X-Target-Proxy-Token`.

The API owns target credentials, adapter selection, sanitization and scope enforcement.

