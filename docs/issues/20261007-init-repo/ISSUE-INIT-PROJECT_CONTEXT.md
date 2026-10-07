# Contexto de Proyecto: Inicialización y Scaffolding de jg_plugin_conversational

## 1. Misión
`jg_plugin_conversational` es el plugin oficial de interacción en lenguaje natural para la plataforma `javiergalvez-ia`.

Proporciona al agente cognitivo capacidades de consulta meteorológica (Azure Maps / simulación) y noticias de actualidad (Europa Press RSS con protección anti-SSRF).

## 2. Estructura y Contratos
- Construido sobre `jg-agente-sdk` (`jg_sdk.contracts`).
- Aislado y desacoplado de `jg_agente` (cero imports de `app.*`).
- Protegido contra SSRF mediante `ssrf_guard.py`.
