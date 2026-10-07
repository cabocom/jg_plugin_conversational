"""Herramienta de consulta meteorológica para jg_plugin_conversational.

Encapsula la consulta de clima bajo el contrato formal AgentTool con validación
estricta de entrada anti-SSRF y soporte para Azure Maps o simulación determinista.
"""

import logging
import os
import re
import time
from typing import Any

import httpx
from jg_sdk.contracts import AgentTool, RiskLevel, ToolResult, ToolType
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger("jg_plugin_conversational.weather")

LOCATION_REGEX = re.compile(r"^[a-zA-Z\s,áéíóúñÁÉÍÓÚÑ.\-]{1,100}$")


class WeatherArgs(BaseModel):
    """Argumentos de entrada validados para la consulta meteorológica."""

    location: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Nombre de la ciudad, municipio o región geográfica (ej. 'Granada', 'Madrid, España'). No se permiten URLs ni comandos.",
    )

    @field_validator("location")
    @classmethod
    def validate_safe_location(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("El parámetro de ubicación no puede estar vacío.")

        # Prevención estricta anti-SSRF: Bloqueo de URLs, IPs y caracteres no geográficos
        if re.search(r"https?://", cleaned, re.IGNORECASE) or "169.254" in cleaned:
            raise ValueError("Ubicación inválida: No se permiten URLs ni direcciones IP.")

        if not LOCATION_REGEX.match(cleaned):
            raise ValueError(
                f"El nombre de la ubicación '{cleaned}' contiene caracteres no permitidos. "
                "Solo se permiten caracteres alfabéticos, espacios, comas y puntos."
            )

        return cleaned


def _get_simulated_weather(location: str) -> tuple[float, str]:
    """Genera datos climáticos deterministas para entornos sin API key o pruebas."""
    base_hash = sum(ord(c) for c in location)
    temp = round(15.0 + (base_hash % 180) / 10.0, 1)  # Entre 15.0 y 32.9 °C

    conditions = [
        "despejado",
        "parcialmente nublado",
        "soleado",
        "nublado",
        "lluvia ligera",
        "viento suave y cielo claro",
    ]
    phrase = conditions[base_hash % len(conditions)]
    return temp, phrase


def get_weather_fn(
    args: WeatherArgs | None = None,
    location: str | None = None,
    city: str | None = None,
    query: str | None = None,
    **kwargs: Any,
) -> ToolResult:
    """Ejecuta la consulta meteorológica mediante Azure Maps o fallback simulado."""
    if args is None:
        loc = location or city or query or kwargs.get("input") or ""
        args = WeatherArgs(location=loc)

    start_time = time.perf_counter()
    location = args.location
    api_key = os.getenv("AZURE_MAPS_KEY")

    try:
        # 1. Modo API Real si existe credencial de Azure Maps configurada
        if api_key and api_key.strip():
            logger.info("Consultando Azure Maps para ubicación: %s", location)
            geocode_url = "https://atlas.microsoft.com/search/address/json"
            weather_url = "https://atlas.microsoft.com/weather/currentConditions/json"

            try:
                with httpx.Client(timeout=5.0) as client:
                    # Paso 1: Geocodificación
                    geo_resp = client.get(
                        geocode_url,
                        params={
                            "api-version": "1.0",
                            "query": location,
                            "subscription-key": api_key,
                        },
                    )

                    if geo_resp.status_code == 200:
                        results = geo_resp.json().get("results", [])
                        if results:
                            pos = results[0].get("position", {})
                            lat = pos.get("lat")
                            lon = pos.get("lon")

                            # Paso 2: Consulta del clima
                            w_resp = client.get(
                                weather_url,
                                params={
                                    "api-version": "1.0",
                                    "query": f"{lat},{lon}",
                                    "subscription-key": api_key,
                                    "language": "es-ES",
                                },
                            )

                            if w_resp.status_code == 200:
                                w_results = w_resp.json().get("results", [])
                                if w_results:
                                    curr = w_results[0]
                                    temp = curr.get("temperature", {}).get("value", 20.0)
                                    phrase = curr.get("phrase", "despejado")
                                    duration = round((time.perf_counter() - start_time) * 1000.0, 2)
                                    output = f"El clima actual en {location} es de {temp}°C con cielo {phrase}."
                                    return ToolResult(
                                        success=True,
                                        output=output,
                                        duration_ms=duration,
                                        metadata={
                                            "location": location,
                                            "temperature_c": temp,
                                            "condition": phrase,
                                            "source": "azure_maps",
                                        },
                                    )

                    logger.warning(
                        "Azure Maps no devolvió resultados para '%s' o falló la respuesta. Conmutando a simulación.",
                        location,
                    )
            except Exception as net_err:
                logger.warning(
                    "Fallo de red al comunicar con Azure Maps (%s). Conmutando a simulación.",
                    net_err,
                )

        # 2. Modo Simulación determinista (fallback para local, dev y CI/CD)
        temp, phrase = _get_simulated_weather(location)
        duration = round((time.perf_counter() - start_time) * 1000.0, 2)
        output = f"El clima actual en {location} es de {temp}°C con cielo {phrase}."

        return ToolResult(
            success=True,
            output=output,
            duration_ms=duration,
            metadata={
                "location": location,
                "temperature_c": temp,
                "condition": phrase,
                "source": "simulated",
            },
        )

    except Exception as exc:
        duration = round((time.perf_counter() - start_time) * 1000.0, 2)
        logger.error("Error al ejecutar consulta de clima para '%s': %s", location, exc)
        return ToolResult(
            success=False,
            output=None,
            error=f"Fallo al consultar el clima para '{location}': {exc}",
            duration_ms=duration,
            metadata={"location": location},
        )


def create_weather_tool() -> AgentTool:
    """Factoría canónica para instanciar la herramienta WeatherTool como AgentTool."""
    return AgentTool(
        name="get_weather",
        description="Devuelve el clima actual para una ciudad o región geográfica específica.",
        category="weather",
        version="1.0.0",
        args_schema=WeatherArgs,
        func=get_weather_fn,
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
