# jg_plugin_conversational

Plugin conversacional oficial (clima y noticias RSS) para la plataforma **jg_agente**, desarrollado y distribuido de forma desacoplada utilizando los contratos formales de **`jg-agente-sdk`**.

---

## 1. Características

- **`get_weather`**: Consulta meteorológica geocodificada en tiempo real (con soporte para Azure Maps Weather API o simulación determinista para testing/CI).
- **`get_news`**: Consulta y parseo seguro de titulares RSS oficiales (Europa Press) con protección contra inyección de prompts y XML seguro (`defusedxml`).
- **Blindaje Anti-SSRF**: Módulo autónomo `ssrf_guard` que realiza resolución DNS con pinning (anti-TOCTOU/DNS Rebinding) y denegación estricta de IPs privadas, loopback, rangos de nube y metadatos.
- **Arquitectura Open-Core Desacoplada**: Depende exclusivamente del paquete formal `jg-agente-sdk` (`jg_sdk.contracts`), sin importaciones directas del core de `jg_agente`.

---

## 2. Instalación y Desarrollo

### Instalación en entorno virtual:

```bash
python3 -m venv .venv
source .venv/bin/activate

# Instalar jg-agente-sdk en modo editable (o desde PyPI)
pip install -e ../jg_agente_sdk

# Instalar jg-plugin-conversational con dependencias de desarrollo
pip install -e ".[dev]"
```

---

## 3. Verificación y Tests

El repositorio incluye una suite completa de pruebas unitarias y de integración autónomas con `MockPluginRunner`:

```bash
# Verificación completa (Ruff linter + formateador + Pytest)
./scripts/check.sh

# O ejecución directa de pytest
pytest -v tests/
```

---

## 4. Integración en `jg_agente`

El plugin expone el entry-point canónico en el grupo `jg_agente.plugins`:

```toml
[project.entry-points."jg_agente.plugins"]
conversational = "jg_plugin_conversational.plugin:ConversationalPlugin"
```

Para activarlo en el runtime del agente (por ejemplo, el contenedor `jg_agente_conversacional`), declare:

```bash
ENABLED_PLUGINS=conversational
# o montaje local como plugin habilitado
```

---

## 5. Licencia

Distribuido bajo licencia GNU Affero General Public License v3 (AGPL-3.0-or-later).
