"""Módulo autónomo de protección y mitigación de Server-Side Request Forgery (SSRF).

Proporciona validación estricta de URLs, resolución DNS segura y transporte HTTP
con mitigación anti-SSRF y DNS Pinning para jg_plugin_conversational.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
from collections.abc import Sequence
from typing import Any
from urllib.parse import urlparse, urlunparse

from jg_plugin_conversational.ssrf_rules import (
    DEFAULT_ALLOWED_SCHEMES,
    DEFAULT_BLOCKED_HOSTNAMES,
    DEFAULT_BLOCKED_NETWORKS,
    SSRFValidationError,
    check_ip_blocked,
)
from jg_plugin_conversational.ssrf_transport import (
    SSRFSafeSyncBackend,
    SSRFSafeTransport,
    create_ssrf_safe_client,
)

logger = logging.getLogger("jg_plugin_conversational.ssrf_guard")


class SSRFGuard:
    """Validador y protector anti-SSRF para peticiones HTTP salientes."""

    def __init__(
        self,
        allowed_hosts: Sequence[str] | None = None,
        allowed_networks: Sequence[str | ipaddress.IPv4Network | ipaddress.IPv6Network]
        | None = None,
        allow_private_networks: bool = False,
        enforce: bool = True,
    ) -> None:
        self.allowed_hosts: set[str] = (
            {h.lower().strip() for h in allowed_hosts if h.strip()} if allowed_hosts else set()
        )
        self.allowed_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        if allowed_networks:
            for net in allowed_networks:
                if isinstance(net, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                    self.allowed_networks.append(net)
                elif isinstance(net, str) and net.strip():
                    try:
                        self.allowed_networks.append(
                            ipaddress.ip_network(net.strip(), strict=False)
                        )
                    except ValueError as exc:
                        logger.warning("Rango de red en allowlist no válido '%s': %s", net, exc)

        self.allow_private_networks = allow_private_networks
        self.enforce = enforce

    def is_ip_allowed_explicitly(
        self,
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> bool:
        """Comprueba si una dirección IP se encuentra en los rangos CIDR permitidos."""
        return any(ip in net for net in self.allowed_networks)

    def is_ip_blocked(
        self,
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> tuple[bool, str | None]:
        """Verifica si una IP está en rangos no autorizados."""
        if self.is_ip_allowed_explicitly(ip):
            return False, None
        return check_ip_blocked(ip, self.allow_private_networks)

    def is_host_allowed_explicitly(self, hostname: str) -> bool:
        """Verifica si el hostname o un comodín de dominio está en la allowlist."""
        host_lower = hostname.lower().strip()
        if host_lower in self.allowed_hosts:
            return True

        for allowed in self.allowed_hosts:
            if allowed.startswith(".") and host_lower.endswith(allowed):
                return True
            if allowed.startswith("*.") and host_lower.endswith(allowed[1:]):
                return True

        return False

    def resolve_host(self, hostname: str, port: int = 80) -> set[str]:
        """Resuelve el hostname de forma sincrónica devolviendo un conjunto de IPs."""
        addr_info = socket.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
        return {str(info[4][0]) for info in addr_info}

    def _validate_pre_dns(
        self, url: str
    ) -> tuple[
        bool, str | None, Any, str | None, ipaddress.IPv4Address | ipaddress.IPv6Address | None
    ]:
        """Comprobaciones preliminares antes de resolución DNS."""
        if not self.enforce:
            return True, None, None, None, None

        if not url or not isinstance(url, str):
            return False, "La URL no puede ser nula o vacía", None, None, None

        try:
            parsed = urlparse(url.strip())
        except Exception as exc:
            return False, f"URL malformada o inválida: {exc}", None, None, None

        scheme = (parsed.scheme or "").lower()
        if scheme not in DEFAULT_ALLOWED_SCHEMES:
            return (
                False,
                f"Esquema de protocolo no permitido '{scheme}'. Permitidos: {DEFAULT_ALLOWED_SCHEMES}",
                parsed,
                None,
                None,
            )

        hostname = parsed.hostname
        if not hostname:
            return False, "La URL no contiene un hostname válido", parsed, None, None

        hostname_lower = hostname.lower().strip()
        if hostname_lower in DEFAULT_BLOCKED_HOSTNAMES:
            return (
                False,
                f"Hostname prohibido por política de seguridad: '{hostname_lower}'",
                parsed,
                hostname_lower,
                None,
            )

        try:
            literal_ip = ipaddress.ip_address(hostname_lower)
            blocked, reason = self.is_ip_blocked(literal_ip)
            if blocked:
                return False, reason, parsed, hostname_lower, literal_ip
            return True, None, parsed, hostname_lower, literal_ip
        except ValueError:
            pass

        return True, None, parsed, hostname_lower, None

    def validate_url(
        self,
        url: str,
        resolve_dns: bool = True,
    ) -> tuple[bool, str | None]:
        """Valida minuciosamente una URL contra ataques SSRF."""
        is_valid, reason, parsed, hostname, literal_ip = self._validate_pre_dns(url)
        if not is_valid:
            return False, reason
        if not self.enforce or literal_ip is not None or not resolve_dns or not hostname:
            return True, None

        try:
            scheme = (parsed.scheme or "").lower()
            port = parsed.port or (443 if scheme == "https" else 80)
            resolved_ips = self.resolve_host(hostname, port)
            if not resolved_ips:
                return False, f"No se pudo resolver la dirección para el host '{hostname}'"

            for ip_str in resolved_ips:
                ip_obj = ipaddress.ip_address(ip_str)
                blocked, reason = self.is_ip_blocked(ip_obj)
                if blocked:
                    return (
                        False,
                        f"El host '{hostname}' resolvió a una dirección no autorizada ({ip_str}): {reason}",
                    )

            return True, None
        except socket.gaierror as exc:
            return False, f"Fallo en la resolución DNS para '{hostname}': {exc}"
        except Exception as exc:
            return False, f"Error durante la validación de red para '{url}': {exc}"

    def resolve_and_pin_url(
        self,
        url: str,
    ) -> tuple[bool, str | None, dict[str, Any] | None]:
        """Valida una URL contra SSRF y retorna metadatos de conexión fijada (DNS Pinning)."""
        is_valid, reason, parsed, hostname, literal_ip = self._validate_pre_dns(url)
        if not is_valid:
            return False, reason, None

        if not self.enforce:
            return True, None, None

        scheme = (parsed.scheme or "http").lower()
        port = parsed.port or (443 if scheme == "https" else 80)

        if literal_ip is not None:
            chosen_ip = str(literal_ip)
        else:
            if not hostname:
                return False, "Hostname ausente", None

            if self.is_host_allowed_explicitly(hostname):
                return True, None, None

            try:
                resolved_ips = self.resolve_host(hostname, port)
            except socket.gaierror as exc:
                return False, f"Fallo en resolución DNS para '{hostname}': {exc}", None
            except Exception as exc:
                return False, f"Error inesperado al resolver '{hostname}': {exc}", None

            if not resolved_ips:
                return (
                    False,
                    f"No se obtuvieron direcciones IP para el host '{hostname}'",
                    None,
                )

            valid_ips: list[str] = []
            for ip_str in resolved_ips:
                ip_obj = ipaddress.ip_address(ip_str)
                blocked, b_reason = self.is_ip_blocked(ip_obj)
                if blocked:
                    return (
                        False,
                        f"Resolución de host '{hostname}' apunta a IP prohibida {ip_str}: {b_reason}",
                        None,
                    )
                valid_ips.append(ip_str)

            valid_ips.sort(key=lambda x: (":" in x, x))
            chosen_ip = valid_ips[0]

        standard_port = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
        host_header = hostname if standard_port else f"{hostname}:{port}"

        ip_obj = ipaddress.ip_address(chosen_ip)
        ip_host_str = f"[{chosen_ip}]" if ip_obj.version == 6 else chosen_ip
        netloc = f"{ip_host_str}:{parsed.port}" if parsed.port else ip_host_str
        pinned_url = urlunparse(
            (
                parsed.scheme,
                netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            )
        )

        pin_info: dict[str, Any] = {
            "hostname": hostname,
            "pinned_ip": chosen_ip,
            "port": port,
            "scheme": scheme,
            "pinned_url": pinned_url,
            "host_header": host_header,
            "headers": {"Host": host_header},
            "dns_pin_map": {hostname.lower(): chosen_ip} if hostname else {},
        }
        return True, None, pin_info


_default_guard: SSRFGuard | None = None
_guard_lock = threading.Lock()


def get_ssrf_validator() -> SSRFGuard:
    """Devuelve la instancia singleton por defecto de SSRFGuard."""
    global _default_guard
    if _default_guard is None:
        with _guard_lock:
            if _default_guard is None:
                _default_guard = SSRFGuard()
    return _default_guard


__all__ = [
    "DEFAULT_ALLOWED_SCHEMES",
    "DEFAULT_BLOCKED_HOSTNAMES",
    "DEFAULT_BLOCKED_NETWORKS",
    "SSRFGuard",
    "SSRFSafeSyncBackend",
    "SSRFSafeTransport",
    "SSRFValidationError",
    "create_ssrf_safe_client",
    "get_ssrf_validator",
]
