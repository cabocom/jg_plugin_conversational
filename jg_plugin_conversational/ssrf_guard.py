"""Módulo autónomo de protección y mitigación de Server-Side Request Forgery (SSRF).

Proporciona validación estricta de URLs, resolución DNS segura y transporte HTTP
con mitigación anti-SSRF y DNS Pinning para jg_plugin_conversational sin depender
del core de jg_agente.
"""

import ipaddress
import logging
import socket
import ssl
import threading
from collections.abc import Sequence
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpcore
import httpx
from httpcore._backends.sync import SyncBackend

logger = logging.getLogger("jg_plugin_conversational.ssrf_guard")


class SSRFValidationError(ValueError):
    """Excepción lanzada cuando una URL, IP o destino vulnera la política anti-SSRF."""

    def __init__(self, message: str, target: str | None = None) -> None:
        super().__init__(message)
        self.target = target


DEFAULT_BLOCKED_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    # IPv4 Loopback
    ipaddress.ip_network("127.0.0.0/8"),
    # IPv4 Link-Local / Metadata Services
    ipaddress.ip_network("169.254.0.0/16"),
    # IPv4 Redes Privadas (RFC 1918)
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # IPv4 Especiales y Reservadas
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6 Loopback y Unspecified
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::/128"),
    # IPv6 Link-Local
    ipaddress.ip_network("fe80::/10"),
    # IPv6 Unique Local Address (ULA - RFC 4193)
    ipaddress.ip_network("fc00::/7"),
    # IPv6 Multicast y Documentación
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("2001:db8::/32"),
]

DEFAULT_BLOCKED_HOSTNAMES: set[str] = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
    "metadata",
    "instance-data",
}

DEFAULT_ALLOWED_SCHEMES: set[str] = {"http", "https"}


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

        for blocked_net in DEFAULT_BLOCKED_NETWORKS:
            if ip in blocked_net:
                is_private_rfc1918 = blocked_net in (
                    ipaddress.ip_network("10.0.0.0/8"),
                    ipaddress.ip_network("172.16.0.0/12"),
                    ipaddress.ip_network("192.168.0.0/16"),
                    ipaddress.ip_network("fc00::/7"),
                )
                if self.allow_private_networks and is_private_rfc1918:
                    continue

                return True, f"IP {ip} bloqueada por pertenecer a rango restringido {blocked_net}"

        return False, None

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


class SSRFSafeSyncBackend(SyncBackend):
    """Backend sincrónico de red para httpcore con protección SSRF y DNS Pinning a nivel TCP."""

    def __init__(
        self,
        dns_pin_map: dict[str, str] | None = None,
        validator: SSRFGuard | None = None,
    ) -> None:
        super().__init__()
        self.dns_pin_map = dns_pin_map or {}
        self.validator = validator or get_ssrf_validator()

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
            is_literal_ip = False
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
            target_ip_obj = None
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
        self._validator = validator or get_ssrf_validator()
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
