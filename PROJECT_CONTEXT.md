# Contexto de Proyecto: jg_plugin_conversational

## 1. Visión y Propósito

`jg_plugin_conversational` es un componente de extensión del ecosistema `javiergalvez-ia` que proporciona capacidades de interacción conversacional en lenguaje natural al agente cognitivo (`jg_agente`).

Forma parte del modelo **Open-Core** de la plataforma:
- **Core (`jg_agente`):** Orquestación, grafos de estado LangGraph, memoria episódica/checkpoints PostgreSQL y gobernanza HITL.
- **SDK (`jg_agente_sdk`):** Contratos normativos y estables (`BasePlugin`, `AgentTool`, `ToolResult`, `RiskLevel`, `ToolType`, `PluginMetadata`).
- **Plugins (`jg_plugin_*`):** Extensiones con ciclo de vida, versionado y repositorios GitLab independientes.

## 2. Estructura del Repositorio

```text
jg_plugin_conversational/
├── .gitignore
├── .gitlab-ci.yml
├── LICENSE
├── README.md
├── PROJECT_CONTEXT.md
├── pyproject.toml
├── scripts/
│   └── check.sh
├── jg_plugin_conversational/
│   ├── __init__.py
│   ├── plugin.py           # Clase canónica ConversationalPlugin (BasePlugin)
│   ├── weather.py          # Herramienta get_weather (Azure Maps / simulación)
│   ├── news.py             # Herramienta get_news (RSS feed Europa Press / simulación)
│   └── ssrf_guard.py       # Helper autónomo de validación de URL y mitigación anti-SSRF
└── tests/
    ├── __init__.py
    ├── test_plugin.py
    ├── test_weather_tool.py
    └── test_news_tool.py
```

## 3. Contratos y Desacoplamiento

- **Cero referencias a `app.*`:** No existe dependencia del código interno de `jg_agente`.
- **Uso estricto de `jg_sdk.contracts`:** Todos los modelos de datos, contratos de herramientas y tipos de riesgo se importan desde el SDK.
- **Protección anti-SSRF autónoma (`ssrf_guard.py`):** Validación exhaustiva de hostnames, IPs privadas, loopbacks y metadatos de proveedores cloud (RFC 1918, RFC 4193, 169.254.0.0/16, etc.) con DNS Pinning anti-TOCTOU.
- **Entry-Point oficial:** Declarado en `pyproject.toml` bajo el grupo `jg_agente.plugins` con el nombre `conversational`.
