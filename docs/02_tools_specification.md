# 02. Especificación de Herramientas (`jg_plugin_conversational`)

[← 01. Arquitectura](01_architecture.md) | [03. Seguridad Anti-SSRF →](03_ssrf_and_sandboxing.md)

---

## 1. Catálogo de Herramientas Canónicas

El plugin provee dos herramientas informativas de solo lectura (`RiskLevel.LOW`):

### 1.1 `get_weather`
- **Tipo:** `observer`
- **Nivel de Riesgo:** `RiskLevel.LOW`
- **Reversibilidad:** No
- **Propósito:** Consulta de condiciones meteorológicas actuales y predicción para una localización dada.
- **Implementación:** Consume la API de Azure Maps o el proveedor local configurado con fallback determinista y protección anti-SSRF.

### 1.2 `get_news`
- **Tipo:** `observer`
- **Nivel de Riesgo:** `RiskLevel.LOW`
- **Reversibilidad:** No
- **Propósito:** Recupera titulares informativos recientes agrupados por temática (nacional, economía, tecnología).
- **Implementación:** Ingesta y parseo de feeds RSS oficiales (Europa Press u homólogos) con sanitización de contenido XML y límite estricto de artículos devueltos.
