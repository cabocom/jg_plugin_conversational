# Documentación Técnica de `jg_plugin_conversational`

Bienvenido a la documentación oficial de **`jg_plugin_conversational`**, plugin para asistencia conversacional, síntesis en lenguaje natural, consulta meteorológica y actualidad informativa bajo aislamiento estricto.

---

## 📚 Índice de Capítulos

1. **[01. Arquitectura del Plugin](es/01_plugin_architecture.md)**
   - Visión del plugin, modelo Open-Core, aislamiento del runtime :8001 y cero acceso a Docker.
2. **[02. Especificación de Herramientas](es/02_tools_specification.md)**
   - Catálogo de herramientas (`get_weather`, `get_news`) y esquemas de parámetros.
3. **[03. Seguridad Anti-SSRF y Aislamiento](es/03_ssrf_and_sandboxing.md)**
   - Guardián autónomo anti-SSRF (`ssrf_guard.py`), DNS Pinning y aislamiento de red en Docker.
4. **[04. Testing, Calidad y CI/CD](es/04_testing_quality_cicd.md)**
   - Suite unitaria Pytest y pipeline de CI/CD.

