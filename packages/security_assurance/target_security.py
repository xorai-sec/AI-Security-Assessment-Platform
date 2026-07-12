from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
import socket
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from .target_models import ConfigurationValidationResult

BLOCKED_EXACT_IPS = {
    ipaddress.ip_address("169.254.169.254"),
}


@dataclass(frozen=True)
class NetworkPolicy:
    allow_local_targets: bool = False
    allow_private_targets: bool = False
    allowed_ports: set[int] = field(default_factory=lambda: {80, 443, 8000, 8001, 8080, 8090, 11434})
    allowed_local_hosts: set[str] = field(default_factory=lambda: {"127.0.0.1", "localhost", "enterprise-assist", "ollama", "vllm"})
    max_redirects: int = 2

    @classmethod
    def from_env(cls) -> NetworkPolicy:
        allow_local = os.getenv("AISEC_ALLOW_LOCAL_TARGETS", "true").lower() in {"1", "true", "yes"}
        allow_private = os.getenv("AISEC_ALLOW_PRIVATE_TARGETS", "false").lower() in {"1", "true", "yes"}
        ports = os.getenv("AISEC_ALLOWED_TARGET_PORTS", "80,443,8000,8001,8080,8090,11434")
        hosts = os.getenv("AISEC_ALLOWED_LOCAL_HOSTS", "127.0.0.1,localhost,enterprise-assist,ollama,vllm")
        return cls(
            allow_local_targets=allow_local,
            allow_private_targets=allow_private,
            allowed_ports={int(port.strip()) for port in ports.split(",") if port.strip().isdigit()},
            allowed_local_hosts={host.strip().lower() for host in hosts.split(",") if host.strip()},
        )


def join_url(base_url: str, path: str | None) -> str:
    if not path:
        return base_url
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def _resolve_host(hostname: str) -> list[ipaddress._BaseAddress]:
    results = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    addresses: list[ipaddress._BaseAddress] = []
    for result in results:
        addresses.append(ipaddress.ip_address(result[4][0]))
    return list(dict.fromkeys(addresses))


def validate_target_url(url: str, policy: NetworkPolicy | None = None) -> ConfigurationValidationResult:
    policy = policy or NetworkPolicy.from_env()
    decisions: list[str] = []
    errors: list[str] = []
    warnings: list[str] = []
    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        errors.append("Only http and https target URLs are supported.")
    else:
        decisions.append(f"Scheme accepted: {parsed.scheme}")

    if not parsed.hostname:
        errors.append("Target URL must include a hostname.")
        return ConfigurationValidationResult(valid=False, errors=errors, warnings=warnings, decisions=decisions)

    hostname = parsed.hostname.lower()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in policy.allowed_ports:
        errors.append(f"Port {port} is not in the administrator-approved target port list.")
    else:
        decisions.append(f"Port accepted: {port}")

    if hostname in policy.allowed_local_hosts and policy.allow_local_targets:
        decisions.append(f"Local laboratory hostname accepted by policy: {hostname}")
        return ConfigurationValidationResult(valid=not errors, errors=errors, warnings=warnings, decisions=decisions)

    try:
        addresses = _resolve_host(hostname)
    except socket.gaierror as exc:
        errors.append(f"DNS resolution failed: {exc}")
        return ConfigurationValidationResult(valid=False, errors=errors, warnings=warnings, decisions=decisions)

    if not addresses:
        errors.append("DNS resolution produced no addresses.")

    for address in addresses:
        decisions.append(f"Resolved {hostname} to {address}")
        if address in BLOCKED_EXACT_IPS:
            errors.append(f"Blocked cloud metadata address: {address}")
        if address.is_loopback and not policy.allow_local_targets:
            errors.append(f"Loopback address blocked by policy: {address}")
        if address.is_private and not policy.allow_private_targets:
            errors.append(f"Private address blocked by policy: {address}")
        if address.is_link_local:
            errors.append(f"Link-local address blocked by policy: {address}")
        if address.is_multicast:
            errors.append(f"Multicast address blocked by policy: {address}")
        if address.is_unspecified:
            errors.append(f"Unspecified address blocked by policy: {address}")

    if parsed.scheme == "http":
        warnings.append("HTTP target uses cleartext transport; HTTPS is recommended for remote targets.")

    return ConfigurationValidationResult(valid=not errors, errors=errors, warnings=warnings, decisions=decisions)


class DevelopmentCredentialProtector:
    """Small environment-key protector for development. Replace with KMS/Vault in enterprise deployments."""

    def __init__(self, key: str | None = None) -> None:
        material = (key or os.getenv("AISEC_CREDENTIAL_KEY") or "development-only-change-me").encode("utf-8")
        self.key = hashlib.sha256(material).digest()

    def encrypt(self, secret: str | None) -> str | None:
        if not secret:
            return None
        data = secret.encode("utf-8")
        stream = self._stream(len(data))
        encrypted = bytes(byte ^ stream[index] for index, byte in enumerate(data))
        return base64.urlsafe_b64encode(encrypted).decode("ascii")

    def decrypt(self, encrypted: str | None) -> str | None:
        if not encrypted:
            return None
        data = base64.urlsafe_b64decode(encrypted.encode("ascii"))
        stream = self._stream(len(data))
        plain = bytes(byte ^ stream[index] for index, byte in enumerate(data))
        return plain.decode("utf-8")

    def preview(self, secret: str | None) -> str | None:
        if not secret:
            return None
        if len(secret) <= 4:
            return "****"
        return f"{secret[:2]}****{secret[-2:]}"

    def _stream(self, length: int) -> bytes:
        out = b""
        counter = 0
        while len(out) < length:
            out += hashlib.sha256(self.key + counter.to_bytes(4, "big")).digest()
            counter += 1
        return out[:length]

