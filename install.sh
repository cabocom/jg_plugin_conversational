#!/usr/bin/env bash
set -e

PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PLUGIN_DIR"

echo "=========================================================="
echo "🚀 Configurando entorno de desarrollo para jg-plugin-conversational"
echo "=========================================================="

# 1. Crear entorno virtual si no existe
if [ ! -d ".venv" ]; then
    echo "📦 Creando entorno virtual en .venv..."
    python3 -m venv .venv
else
    echo "ℹ️  Entorno virtual .venv ya existente."
fi

VENV_PIP="$PLUGIN_DIR/.venv/bin/pip"

# 2. Instalar o enlazar jg-agente-sdk
SDK_LOCAL_PATH="../jg_agente_sdk"
if [ -d "$SDK_LOCAL_PATH" ] && [ -f "$SDK_LOCAL_PATH/pyproject.toml" ]; then
    echo "🔗 Vinculando jg-agente-sdk desde repositorio local ($SDK_LOCAL_PATH)..."
    "$VENV_PIP" install -e "$SDK_LOCAL_PATH"
else
    echo "🌐 Instalando jg-agente-sdk desde índice de paquetes..."
    "$VENV_PIP" install "jg-agente-sdk>=1.0.0"
fi

# 3. Instalar dependencias de desarrollo y el plugin en modo editable
echo "📥 Instalando jg-plugin-conversational en modo editable..."
"$VENV_PIP" install -e ".[dev]"

echo ""
echo "=========================================================="
echo "✅ Instalación completada con éxito."
echo ""
echo "Para comenzar a trabajar, activa el entorno virtual:"
echo "   source .venv/bin/activate"
echo ""
echo "Para ejecutar la suite de pruebas:"
echo "   pytest tests/"
echo "=========================================================="
