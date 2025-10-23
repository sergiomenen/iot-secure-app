#!/usr/bin/env bash
# Script de preparación local para iot-secure-app
# - Crea y activa un entorno virtual
# - Instala dependencias desde requirements.txt
# - Imprime instrucciones para ejecutar la app con Streamlit
set -euo pipefail

# Detectar Python 3
if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo "ERROR: Python 3 no encontrado en el PATH." >&2
  exit 1
fi

# Crear venv
VENV_DIR=".venv"
if [ ! -d "$VENV_DIR" ]; then
  echo ">> Creando entorno virtual en $VENV_DIR ..."
  "$PY" -m venv "$VENV_DIR"
else
  echo ">> Entorno virtual ya existe en $VENV_DIR"
fi

# Activar venv (shell bash/zsh)
# Nota: si usas fish o csh, activa según tu shell.
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

# Actualizar pip y wheel
echo ">> Actualizando pip y wheel ..."
pip install --upgrade pip wheel

# Instalar dependencias
echo ">> Instalando dependencias desde requirements.txt ..."
pip install -r requirements.txt

echo
echo "✅ Entorno listo."
echo
echo "Para ejecutar la app de Streamlit:"
echo "  source $VENV_DIR/bin/activate"
echo "  streamlit run app.py"
echo
echo "Para correr pruebas (opcional):"
echo "  pytest -q"
echo
echo "Nota: este script no inicia servicios ni abre túneles; todo es local-only."
