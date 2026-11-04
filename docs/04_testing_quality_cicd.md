# 04. Testing, Calidad y CI/CD (`jg_plugin_conversational`)

[← 03. Seguridad Anti-SSRF](03_ssrf_and_sandboxing.md) | [Volver al Índice](README.md)

---

## 1. Suite de Pruebas Automatizadas

El plugin dispone de una suite en Pytest con pruebas unitarias para:
- `test_weather_tool.py`: Simulación de respuestas meteorológicas y validación de fallbacks.
- `test_news_tool.py`: Parseo de feeds RSS y sanitización de noticias.
- `test_plugin.py`: Ciclo de vida con `MockPluginRunner` del SDK.

---

## 2. Pipeline de CI/CD

El script `scripts/check.sh` y el pipeline en GitLab ejecutan:
1. `ruff check .` y `ruff format --check .`
2. `pytest tests/`
3. Empaquetado de biblioteca `python -m build`.
