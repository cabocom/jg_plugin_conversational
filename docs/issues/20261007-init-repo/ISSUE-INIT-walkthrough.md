# Walkthrough: Inicialización de jg_plugin_conversational

1. Inicializado repositorio Git independiente y configurado remote `origin` hacia `git@gitlab.com:javiergalvez-ia/jg_plugin_conversational.git`.
2. Creados archivos de empaquetado, integración continua y verificación:
   - `pyproject.toml`
   - `.gitlab-ci.yml`
   - `.gitignore`
   - `LICENSE`
   - `README.md`
   - `PROJECT_CONTEXT.md`
   - `install.sh`
   - `scripts/check.sh`
3. Implementado paquete Python `jg_plugin_conversational`:
   - `plugin.py`, `weather.py`, `news.py`, `ssrf_guard.py`, `__init__.py`.
4. Implementada suite de 25 pruebas unitarias autónomas en `tests/`.
5. Verificado con `scripts/check.sh` (100% verde).
