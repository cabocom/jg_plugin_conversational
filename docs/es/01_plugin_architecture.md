# 01. Arquitectura del Plugin (`jg_plugin_conversational`)

[← Volver al Índice](README.md) | [02. Especificación de Herramientas →](02_tools_specification.md)

---

## 1. Visión y Propósito

`jg_plugin_conversational` es la extensión del ecosistema `javiergalvez-ia` especializada en asistencia conversacional general, síntesis de respuestas en lenguaje natural, consulta meteorológica y actualidad informativa.

Forma parte del modelo **Open-Core**:
- Se despliega en su propio runtime aislado (`jg_agente_conversacional` en el puerto `8001`).
- **Aislamiento Total de Entorno:** No tiene acceso al socket de Docker, carece de herramientas mutativas y opera con permisos mínimos de red.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        CONSULTA CONVERSACIONAL                         │
│           ("¿Qué tiempo hace en Madrid y qué noticias hay?")           │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ MOTOR COGNITIVO AISLADO (jg_agente_conversacional :8001)               │
│                                                                        │
│   ┌───────────────────────────┐     ┌───────────────────────────────┐  │
│   │ get_weather (weather.py)  │     │ get_news (news.py)            │  │
│   │ - Azure Maps / Simulación │     │ - RSS Europa Press / Simulado │  │
│   └─────────────┬─────────────┘     └───────────────┬───────────────┘  │
│                 │                                   │                  │
│                 └─────────────────┬─────────────────┘                  │
│                                   │                                    │
│                                   ▼                                    │
│             ┌───────────────────────────────────────────┐              │
│             │   Protección Anti-SSRF (ssrf_guard.py)    │              │
│             │   DNS Pinning anti-TOCTOU + IP Whitelist  │              │
│             └───────────────────────────────────────────┘              │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Desacoplamiento y Contratos

- Implementa `BasePlugin` de `jg_agente_sdk`.
- Cero dependencias de `jg_agente` (`app.*`).
- Entry-point registrado en `pyproject.toml` bajo `jg_agente.plugins` con el nombre `conversational`.

