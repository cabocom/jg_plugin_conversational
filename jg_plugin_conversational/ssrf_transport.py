"""Transporte HTTP seguro y backend con mitigación anti-SSRF para jg_plugin_conversational."""

from __future__ import annotations

import ipaddress
import ssl
from typing import TYPE_CHECKING, Any

import httpcore
import httpx
from httpcore._backends.sync import SyncBackend

from jg_plugin_conversational.ssrf_rules import SSRFValidationError

if TYPE_CHECKING:
    from jg_plugin_conversational.ssrf_guard import SSRFGuard


class SSRFSafeSyncBackend(SyncBackend):
    """Backend sincrónico de red para httpcore con protección SSRF y DNS Pinning a nivel TCP."""

    def __init__(
        self,
        dns_pin_map: dict[str, str] | None = None,
        validator: SSRFGuard | None = None,
    ) -> None:
        super().__init__()
        self.dns_pin_map = dns_pin_map or {}
        if validator is None:
            from jg_plugin_conversational.ssrf_guard import get_ssrf_validator

            validator = get_ssrf_validator()
        self.validator = validator

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> Any:
        target_host = host
        host_lower = host.lower()

        if host_lower in self.dns_pin_map:
            target_host = self.dns_pin_map[host_lower]
        else:
            try:
                ipaddress.ip_address(host)
                is_literal_ip = True
            except ValueError:
                is_literal_ip = False

            if (
                not is_literal_ip
                and self.validator.enforce
                and not self.validator.is_host_allowed_explicitly(host_lower)
            ):
                resolved = self.validator.resolve_host(host, port)
                if not resolved:
                    raise SSRFValidationError(
                        f"No se pudo resolver la dirección para el host '{host}'",
                        target=host,
                    )
                for ip_str in resolved:
                    ip_obj = ipaddress.ip_address(ip_str)
                    blocked, reason = self.validator.is_ip_blocked(ip_obj)
                    if blocked:
                        raise SSRFValidationError(
                            f"Resolución de host '{host}' apunta a IP prohibida {ip_str}: {reason}",
                            target=host,
                        )
                sorted_ips = sorted(resolved, key=lambda x: (":" in x, x))
                target_host = sorted_ips[0]

        if self.validator.enforce:
            try:
                target_ip_obj = ipaddress.ip_address(target_host)
            except ValueError:
                target_ip_obj = None

            if target_ip_obj is not None:
                blocked, reason = self.validator.is_ip_blocked(target_ip_obj)
                if blocked:
                    raise SSRFValidationError(
                        f"Conexión TCP bloqueada a IP prohibida {target_host}: {reason}",
                        target=target_host,
                    )

        return super().connect_tcp(
            host=target_host,
            port=port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )


class SSRFSafeTransport(httpx.HTTPTransport):
    """Transporte HTTP sincrónico para httpx con mitigación activa contra SSRF y DNS Rebinding."""

    def __init__(
        self,
        dns_pin_map: dict[str, str] | None = None,
        validator: SSRFGuard | None = None,
        verify: ssl.SSLContext | str | bool = True,
        **kwargs: Any,
    ) -> None:
        super().__init__(verify=verify, **kwargs)
        self._dns_pin_map = dns_pin_map or {}
        if validator is None:
            from jg_plugin_conversational.ssrf_guard import get_ssrf_validator

            validator = get_ssrf_validator()
        self._validator = validator
        self._pool = httpcore.ConnectionPool(
            ssl_context=getattr(self._pool, "_ssl_context", None),
            max_connections=getattr(self._pool, "_max_connections", 10),
            max_keepalive_connections=getattr(self._pool, "_max_keepalive_connections", None),
            keepalive_expiry=getattr(self._pool, "_keepalive_expiry", None),
            http1=getattr(self._pool, "_http1", True),
            http2=getattr(self._pool, "_http2", False),
            network_backend=SSRFSafeSyncBackend(
                dns_pin_map=self._dns_pin_map,
                validator=self._validator,
            ),
        )


def create_ssrf_safe_client(
    dns_pin_map: dict[str, str] | None = None,
    validator: SSRFGuard | None = None,
    timeout: float | httpx.Timeout = 10.0,
    verify: ssl.SSLContext | str | bool = True,
    **kwargs: Any,
) -> httpx.Client:
    """Crea un cliente httpx sincrónico seguro contra SSRF y DNS Rebinding."""
    transport = SSRFSafeTransport(
        dns_pin_map=dns_pin_map,
        validator=validator,
        verify=verify,
    )
    return httpx.Client(transport=transport, timeout=timeout, **kwargs)


__all__ = [
    "SSRFSafeSyncBackend",
    "SSRFSafeTransport",
    "create_ssrf_safe_client",
]
