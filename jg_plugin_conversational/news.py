"""Herramienta de consulta de noticias para jg_plugin_conversational.

Encapsula la obtención de noticias informativas (Europa Press RSS) bajo el contrato
formal AgentTool con validación estricta de parámetros, protección anti-SSRF desacoplada
mediante SSRFGuard y datos limpios sin inyección de pseudo-prompts.
"""

import logging
import re
import time
from typing import Any

import defusedxml.ElementTree as ET
from jg_sdk.contracts import AgentTool, RiskLevel, ToolResult, ToolType
from pydantic import BaseModel, Field, field_validator

from jg_plugin_conversational.ssrf_guard import (
    SSRFValidationError,
    create_ssrf_safe_client,
    get_ssrf_validator,
)

logger = logging.getLogger("jg_plugin_conversational.news")

TOPIC_REGEX = re.compile(r"^[a-zA-ZáéíóúñÁÉÍÓÚÑ\s\-]{1,50}$")

RSS_CHANNELS: dict[str, str] = {
    "general": "https://www.europapress.es/rss/rss.aspx",
    "actualidad": "https://www.europapress.es/rss/rss.aspx",
    "nacional": "https://www.europapress.es/rss/rss.aspx?ch=00066",
    "economia": "https://www.europapress.es/rss/rss.aspx?ch=00066",
    "internacional": "https://www.europapress.es/rss/rss.aspx?ch=00069",
    "deportes": "https://www.europapress.es/rss/rss.aspx?ch=00067",
}


class NewsArgs(BaseModel):
    """Argumentos validados de entrada para la consulta de noticias."""

    topic: str = Field(
        default="general",
        max_length=50,
        description="Temática de interés (ej. 'general', 'economia', 'deportes', 'internacional').",
    )
    limit: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Número máximo de noticias a devolver (entre 1 y 10).",
    )

    @field_validator("topic")
    @classmethod
    def validate_safe_topic(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if not cleaned:
            return "general"

        # Prevención estricta anti-SSRF: Bloqueo de URLs, IPs y comandos
        if re.search(r"https?://", cleaned, re.IGNORECASE) or "169.254" in cleaned:
            raise ValueError("Tema inválido: No se permiten URLs ni direcciones IP.")

        if not TOPIC_REGEX.match(cleaned):
            raise ValueError(
                f"El tema '{cleaned}' contiene caracteres no permitidos. "
                "Solo se permiten caracteres alfabéticos, espacios y guiones."
            )

        return cleaned


def _get_simulated_news(topic: str, limit: int) -> list[dict[str, str]]:
    """Genera noticias simuladas deterministas para entornos sin conexión o pruebas."""
    samples = {
        "general": [
            {
                "title": "Avances en la modernización de infraestructuras energéticas en España",
                "summary": "El plan nacional prevé una inversión récord en redes inteligentes.",
            },
            {
                "title": "La conferencia europea de innovación debate el futuro de la automatización",
                "summary": "Expertos del sector analizan nuevos marcos de seguridad y gobernanza.",
            },
            {
                "title": "Nuevas medidas de sostenibilidad para el transporte metropolitano",
                "summary": "Entran en vigor normativas destinadas a reducir la huella de carbono.",
            },
        ],
        "economia": [
            {
                "title": "Los mercados financieros cierran la semana con tendencia estable",
                "summary": "Los índices bursátiles europeos consolidan ganancias moderadas.",
            },
            {
                "title": "El sector tecnológico lidera el incremento de empleo especializado",
                "summary": "La demanda de perfiles en ingeniería y nube crece un 15% este trimestre.",
            },
            {
                "title": "Se acelera la digitalización en pequeñas y medianas empresas industriales",
                "summary": "Las inversiones en plataformas digitales alcanzan máximos anuales.",
            },
        ],
        "deportes": [
            {
                "title": "La liga nacional entra en su fase decisiva con máxima igualdad en la tabla",
                "summary": "Los primeros clasificados disputan encuentros clave este fin de semana.",
            },
            {
                "title": "Récord de participación en la media maratón de la capital",
                "summary": "Miles de atletas completan el recorrido urbano en una jornada festiva.",
            },
        ],
    }

    selected = samples.get(topic, samples["general"])
    return selected[:limit]


def get_news_fn(
    args: NewsArgs | None = None,
    topic: str | None = None,
    limit: int | None = None,
    query: str | None = None,
    validator: Any = None,
    **kwargs: Any,
) -> ToolResult:
    """Consulta titulares de noticias desde Europa Press RSS o fallback determinista."""
    if args is None:
        raw_topic = topic or query or kwargs.get("input") or "general"
        raw_limit = limit if limit is not None else 5
        args = NewsArgs(topic=raw_topic, limit=raw_limit)

    start_time = time.perf_counter()
    topic = args.topic.lower()
    limit = args.limit
    rss_url = RSS_CHANNELS.get(topic, RSS_CHANNELS["general"])

    # 1. Validación de seguridad SSRF con DNS Pinning anti-TOCTOU
    ssrf_validator = validator or kwargs.get("ssrf_validator") or get_ssrf_validator()
    is_valid, reason, pin_info = ssrf_validator.resolve_and_pin_url(rss_url)

    is_dns_failure = False
    if not is_valid:
        reason_str = (reason or "").lower()
        if (
            "resolución dns" in reason_str
            or "resolver" in reason_str
            or "dns" in reason_str
            or "nodename nor servname" in reason_str
        ):
            logger.warning(
                "Ausencia de resolución DNS al validar RSS de noticias (%s): %s. "
                "Conmutando a simulación determinista.",
                rss_url,
                reason,
            )
            is_dns_failure = True
        else:
            logger.error(
                "Bloqueo SSRF al intentar consultar RSS de noticias: %s (%s)", rss_url, reason
            )
            raise SSRFValidationError(
                f"Destino de noticias no autorizado por política SSRF: {reason}"
            )

    if not is_dns_failure and pin_info:
        try:
            # 2. Intento de consulta en vivo vía HTTP con cliente seguro y DNS Pinning
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
                "Accept": "application/rss+xml, application/xml, text/xml",
            }
            headers.update(pin_info.get("headers", {}))

            with create_ssrf_safe_client(
                dns_pin_map=pin_info.get("dns_pin_map"),
                validator=ssrf_validator,
                timeout=5.0,
            ) as client:
                resp = client.get(rss_url, headers=headers)
                if resp.status_code == 200 and resp.content:
                    # 3. Parseo seguro de XML con defusedxml
                    root = ET.fromstring(resp.content)
                    items = root.findall(".//item")

                    if items:
                        articles: list[dict[str, str]] = []
                        for item in items[:limit]:
                            title_elem = item.find("title")
                            desc_elem = item.find("description")
                            link_elem = item.find("link")

                            title = (
                                title_elem.text.strip()
                                if title_elem is not None and title_elem.text
                                else "Sin título"
                            )
                            desc = (
                                desc_elem.text.strip()
                                if desc_elem is not None and desc_elem.text
                                else ""
                            )
                            link = (
                                link_elem.text.strip()
                                if link_elem is not None and link_elem.text
                                else ""
                            )

                            # Limpieza de etiquetas HTML en descripción
                            clean_desc = re.sub(r"<[^>]+>", "", desc).strip()
                            articles.append({"title": title, "summary": clean_desc, "link": link})

                        duration = round((time.perf_counter() - start_time) * 1000.0, 2)
                        output_lines = [
                            f"Últimas noticias de Europa Press (tema: {topic}):",
                        ]
                        for idx, art in enumerate(articles, 1):
                            output_lines.append(f"{idx}. {art['title']}")
                            if art["summary"]:
                                output_lines.append(f"   {art['summary']}")

                        return ToolResult(
                            success=True,
                            output="\n".join(output_lines),
                            duration_ms=duration,
                            metadata={
                                "topic": topic,
                                "count": len(articles),
                                "articles": articles,
                                "source": "europapress_rss",
                            },
                        )

        except Exception as exc:
            logger.warning(
                "Fallo de red o parseo al consultar Europa Press RSS (%s). Conmutando a simulación.",
                exc,
            )

    # 4. Fallback a simulación determinista (offline / dev / tests)
    simulated = _get_simulated_news(topic, limit)
    duration = round((time.perf_counter() - start_time) * 1000.0, 2)
    output_lines = [
        f"Últimas noticias de actualidad (tema: {topic}):",
    ]
    for idx, art in enumerate(simulated, 1):
        output_lines.append(f"{idx}. {art['title']}")
        if art["summary"]:
            output_lines.append(f"   {art['summary']}")

    return ToolResult(
        success=True,
        output="\n".join(output_lines),
        duration_ms=duration,
        metadata={
            "topic": topic,
            "count": len(simulated),
            "articles": simulated,
            "source": "simulated",
        },
    )


def create_news_tool() -> AgentTool:
    """Factoría canónica para instanciar NewsTool como AgentTool."""
    return AgentTool(
        name="get_news",
        description="Devuelve las últimas noticias de actualidad general o por temática desde fuentes informativas oficiales.",
        category="news",
        version="1.0.0",
        args_schema=NewsArgs,
        func=get_news_fn,
        risk_level=RiskLevel.LOW,
        required_permissions=[],
        tool_type=ToolType.READ,
        read_only=True,
        reversible=False,
        idempotent=True,
        makes_http_requests=True,
        timeout_sec=5.0,
        rollback_func=None,
    )
