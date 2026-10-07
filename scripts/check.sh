#!/usr/bin/env bash
set -e

# Directorio base de jg_plugin_conversational
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Determinar ejecutables
if [ -f "$PROJECT_ROOT/.venv/bin/pytest" ]; then
    PYTEST="$PROJECT_ROOT/.venv/bin/pytest"
elif [ -f "$PROJECT_ROOT/../jg_agente/.venv/bin/pytest" ]; then
    PYTEST="$PROJECT_ROOT/../jg_agente/.venv/bin/pytest"
elif [ -f "$PROJECT_ROOT/../jg_agente_sdk/.venv/bin/pytest" ]; then
    PYTEST="$PROJECT_ROOT/../jg_agente_sdk/.venv/bin/pytest"
else
    PYTEST="pytest"
fi

if [ -f "$PROJECT_ROOT/.venv/bin/ruff" ]; then
    RUFF="$PROJECT_ROOT/.venv/bin/ruff"
elif [ -f "$PROJECT_ROOT/../jg_agente/.venv/bin/ruff" ]; then
    RUFF="$PROJECT_ROOT/../jg_agente/.venv/bin/ruff"
elif [ -f "$PROJECT_ROOT/../jg_agente_sdk/.venv/bin/ruff" ]; then
    RUFF="$PROJECT_ROOT/../jg_agente_sdk/.venv/bin/ruff"
elif command -v ruff >/dev/null 2>&1; then
    RUFF="$(command -v ruff)"
else
    RUFF=""
fi

echo "========================================"
echo "🔍 Verificando jg_plugin_conversational..."
echo "========================================"

if [ -n "$RUFF" ]; then
    echo ""
    echo "1️⃣  [Ruff] Linter y formato de código..."
    "$RUFF" check .
    "$RUFF" format --check .
fi

echo ""
echo "2️⃣  [Pytest] Ejecución de suite de tests unitarios del plugin..."
PYTHONPATH="$PROJECT_ROOT:$PROJECT_ROOT/../jg_agente_sdk" "$PYTEST" -v tests

echo ""
echo "========================================"
echo "✅ ¡Todas las comprobaciones de jg_plugin_conversational pasaron con éxito!"
echo "========================================"
