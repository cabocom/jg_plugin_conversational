"""Reglas estáticas, rangos de red y excepciones para mitigación de SSRF."""

from __future__ import annotations

import ipaddress
import logging

logger = logging.getLogger("jg_plugin_conversational.ssrf_rules")


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

RFC1918_NETWORKS = {
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
}


def check_ip_blocked(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    allow_private_networks: bool = False,
) -> tuple[bool, str | None]:
    """Verifica si una IP se encuentra dentro de los rangos restringidos."""
    for blocked_net in DEFAULT_BLOCKED_NETWORKS:
        if ip in blocked_net:
            if allow_private_networks and blocked_net in RFC1918_NETWORKS:
                continue
            return True, f"IP {ip} bloqueada por pertenecer a rango restringido {blocked_net}"
    return False, None


__all__ = [
    "DEFAULT_ALLOWED_SCHEMES",
    "DEFAULT_BLOCKED_HOSTNAMES",
    "DEFAULT_BLOCKED_NETWORKS",
    "RFC1918_NETWORKS",
    "SSRFValidationError",
    "check_ip_blocked",
]
