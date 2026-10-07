"""Tests unitarios y de integración para el paquete jg_plugin_conversational."""

import ast
from pathlib import Path

import pytest
from jg_sdk.contracts import BasePlugin, PluginMetadata
from jg_sdk.testing import MockPluginRunner

from jg_plugin_conversational import PLUGIN_CLASS, ConversationalPlugin, __version__


def test_import_and_plugin_class_contract() -> None:
    """Verifica que el paquete se importa independientemente y expone PLUGIN_CLASS válido."""
    assert PLUGIN_CLASS is not None
    assert issubclass(PLUGIN_CLASS, BasePlugin)
    assert PLUGIN_CLASS is ConversationalPlugin
    assert __version__ == "1.0.0"

    plugin = PLUGIN_CLASS()
    assert isinstance(plugin, BasePlugin)
    assert plugin.name == "conversational"


def test_plugin_metadata() -> None:
    """Valida los metadatos canónicos del plugin conversacional."""
    plugin = ConversationalPlugin()
    meta = plugin.get_plugin_metadata()

    assert isinstance(meta, PluginMetadata)
    assert meta.name == "conversational"
    assert meta.version == "1.0.0"
    assert meta.dependencies == []
    assert meta.jg_agente_version_min == "0.1.0"
    assert "conversational" in meta.tags
    assert "nlp" in meta.tags
    assert "weather" in meta.tags
    assert "news" in meta.tags


def test_register_tools_and_engines_contracts() -> None:
    """Valida los métodos obligatorios de registro de herramientas y motores."""
    plugin = ConversationalPlugin()

    tools = plugin.register_tools()
    assert isinstance(tools, list)
    assert len(tools) == 2
    tool_names = {t.name for t in tools}
    assert "get_weather" in tool_names
    assert "get_news" in tool_names

    engines = plugin.register_engines()
    assert isinstance(engines, dict)
    assert len(engines) == 0

    models = plugin.register_models()
    assert isinstance(models, dict)


@pytest.mark.asyncio
async def test_async_lifecycle() -> None:
    """Valida el ciclo de vida asíncrono con startup, shutdown y health_check."""
    plugin = ConversationalPlugin()
    assert plugin._is_started is False

    async with plugin:
        assert plugin._is_started is True
        health = await plugin.health_check()
        assert health["status"] == "ok"
        assert health["plugin"] == "conversational"
        assert health["version"] == "1.0.0"
        assert health["started"] is True

    assert plugin._is_started is False


@pytest.mark.asyncio
async def test_mock_plugin_runner_integration() -> None:
    """Verifica la compatibilidad con el harness canónico MockPluginRunner de jg_agente_sdk."""
    plugin = ConversationalPlugin()
    runner = MockPluginRunner(plugin)

    async with runner:
        assert runner.metadata.name == "conversational"
        assert len(runner.list_tools()) == 2
        weather_tool = runner.get_tool("get_weather")
        assert weather_tool is not None
        assert weather_tool.name == "get_weather"

        news_tool = runner.get_tool("get_news")
        assert news_tool is not None
        assert news_tool.name == "get_news"

        health = await runner.health_check()
        assert health["status"] == "ok"


def test_strict_isolation_no_devops_or_asterisk() -> None:
    """Garantiza ausencia total de dependencias o imports hacia DevOps o Asterisk directo."""
    pkg_dir = Path(__file__).parent.parent / "jg_plugin_conversational"
    py_files = list(pkg_dir.glob("*.py"))
    assert py_files, "No se encontraron archivos de código en el plugin"

    forbidden_terms = ["docker", "kubernetes", "k8s", "devops", "asterisk", "ari", "pjsip"]

    for py_file in py_files:
        tree = ast.parse(py_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    for term in forbidden_terms:
                        assert term not in alias.name.lower(), (
                            f"Import indebido detectado en {py_file.name}: {alias.name}"
                        )
            elif isinstance(node, ast.ImportFrom):
                mod_name = node.module or ""
                for term in forbidden_terms:
                    assert term not in mod_name.lower(), (
                        f"ImportFrom indebido detectado en {py_file.name}: {mod_name}"
                    )


def test_strict_no_core_app_imports() -> None:
    """Garantiza desacoplamiento absoluto de jg_agente (cero imports de app.*)."""
    pkg_dir = Path(__file__).parent.parent
    py_files = list(pkg_dir.glob("**/*.py"))
    assert py_files, "No se encontraron archivos Python en el repositorio"

    for py_file in py_files:
        if ".venv" in str(py_file):
            continue
        tree = ast.parse(py_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith("app."), (
                        f"Import directo de core app.* en {py_file}: {alias.name}"
                    )
            elif isinstance(node, ast.ImportFrom):
                mod_name = node.module or ""
                assert not mod_name.startswith("app."), (
                    f"ImportFrom directo de core app.* en {py_file}: {mod_name}"
                )
