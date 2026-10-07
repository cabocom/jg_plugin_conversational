"""Tests unitarios y de integración para WeatherTool y WeatherArgs en jg_plugin_conversational."""

from unittest.mock import MagicMock, patch

import pytest
from jg_sdk.contracts import AgentTool, RiskLevel, ToolResult
from jg_sdk.testing import MockPluginRunner
from pydantic import ValidationError

from jg_plugin_conversational.plugin import ConversationalPlugin
from jg_plugin_conversational.weather import (
    WeatherArgs,
    create_weather_tool,
    get_weather_fn,
)


def test_weather_args_valid_locations() -> None:
    """Verifica que WeatherArgs acepta nombres geográficos legítimos."""
    valid_locations = [
        "Granada",
        "Madrid, España",
        "Sevilla",
        "San Sebastián",
        "Buenos Aires",
        "St. Louis",
        "Alcalá de Henares",
        "A Coruña",
    ]
    for loc in valid_locations:
        args = WeatherArgs(location=loc)
        assert args.location == loc


def test_weather_args_rejection_anti_ssrf_and_invalid() -> None:
    """Verifica el rechazo estricto de URLs, IPs y comandos maliciosos anti-SSRF."""
    invalid_locations = [
        "http://169.254.169.254/latest/meta-data/",
        "https://malicious.example.com",
        "169.254.169.254",
        "Madrid; rm -rf /",
        "Granada && cat /etc/passwd",
        "<script>alert(1)</script>",
        "",
        "   ",
        "A" * 105,  # Excede max_length 100
    ]
    for inv in invalid_locations:
        with pytest.raises((ValidationError, ValueError)):
            WeatherArgs(location=inv)


def test_weather_tool_contract_attributes() -> None:
    """Verifica que la herramienta satisface todos los requisitos del contrato AgentTool."""
    tool = create_weather_tool()

    assert isinstance(tool, AgentTool)
    assert tool.name == "get_weather"
    assert tool.category == "weather"
    assert tool.version == "1.0.0"
    assert tool.args_schema is WeatherArgs
    assert callable(tool.func)
    assert tool.risk_level == RiskLevel.LOW
    assert tool.read_only is True
    assert tool.reversible is False
    assert tool.idempotent is True
    assert tool.makes_http_requests is True
    assert tool.timeout_sec == 5.0
    assert tool.rollback_func is None


def test_weather_simulated_execution() -> None:
    """Verifica que la ejecución en modo simulado retorna un ToolResult estructurado y determinista."""
    tool = create_weather_tool()
    args = WeatherArgs(location="Granada")

    # Sin AZURE_MAPS_KEY configurada se ejecuta en modo simulación
    with patch.dict("os.environ", {}, clear=True):
        result = tool.func(args)

    assert isinstance(result, ToolResult)
    assert result.success is True
    assert "Granada" in result.output
    assert "°C" in result.output
    assert result.duration_ms >= 0.0
    assert result.metadata.get("location") == "Granada"
    assert result.metadata.get("source") == "simulated"
    assert "temperature_c" in result.metadata


def test_weather_azure_maps_mocked_execution() -> None:
    """Verifica la interacción con Azure Maps cuando la API Key está configurada."""
    mock_geocode_resp = MagicMock()
    mock_geocode_resp.status_code = 200
    mock_geocode_resp.json.return_value = {
        "results": [{"position": {"lat": 37.1773, "lon": -3.5986}}]
    }

    mock_weather_resp = MagicMock()
    mock_weather_resp.status_code = 200
    mock_weather_resp.json.return_value = {
        "results": [{"temperature": {"value": 24.5}, "phrase": "soleado y claro"}]
    }

    mock_client_instance = MagicMock()
    mock_client_instance.get.side_effect = [mock_geocode_resp, mock_weather_resp]

    with (
        patch.dict("os.environ", {"AZURE_MAPS_KEY": "valid-azure-maps-key"}),
        patch("httpx.Client") as mock_client_cls,
    ):
        mock_client_cls.return_value.__enter__.return_value = mock_client_instance

        result = get_weather_fn(WeatherArgs(location="Granada"))

    assert isinstance(result, ToolResult)
    assert result.success is True
    assert "24.5°C" in result.output
    assert "soleado y claro" in result.output
    assert result.metadata.get("source") == "azure_maps"
    assert result.metadata.get("temperature_c") == 24.5


def test_weather_azure_maps_network_error_fallback() -> None:
    """Verifica que ante fallo de conectividad con Azure Maps conmuta grácilmente a simulación."""
    mock_client_instance = MagicMock()
    mock_client_instance.get.side_effect = Exception("Conexión rechazada con Azure Maps")

    with (
        patch.dict("os.environ", {"AZURE_MAPS_KEY": "some-key"}),
        patch("httpx.Client") as mock_client_cls,
    ):
        mock_client_cls.return_value.__enter__.return_value = mock_client_instance

        result = get_weather_fn(WeatherArgs(location="Granada"))

    assert isinstance(result, ToolResult)
    assert result.success is True
    assert "Granada" in result.output


def test_conversational_plugin_register_tools() -> None:
    """Verifica que ConversationalPlugin expone get_weather en su catálogo de herramientas."""
    plugin = ConversationalPlugin()
    tools = plugin.register_tools()
    tool_names = [t.name for t in tools]
    assert "get_weather" in tool_names
    weather_tool = next(t for t in tools if t.name == "get_weather")
    assert weather_tool.category == "weather"
    assert weather_tool.risk_level == RiskLevel.LOW


@pytest.mark.asyncio
async def test_weather_execution_via_mock_runner() -> None:
    """Verifica la invocación completa de get_weather a través de MockPluginRunner."""
    plugin = ConversationalPlugin()
    runner = MockPluginRunner(plugin)

    async with runner:
        weather_tool = runner.get_tool("get_weather")
        assert weather_tool is not None
        assert weather_tool.read_only is True

        result = weather_tool.func(WeatherArgs(location="Sevilla"))
        assert isinstance(result, ToolResult)
        assert result.success is True
        assert "Sevilla" in result.output
        assert result.metadata.get("location") == "Sevilla"
