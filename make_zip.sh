#!/usr/bin/env bash
# make_zip.sh
# Script auxiliar local para empaquetar el proyecto iot-secure-app
# Verifica que los ficheros principales existen y ejecuta pack_for_students.py
# No usa red ni descarga nada.

set -euo pipefail

# Ruta base del proyecto (directorio actual)
ROOT_DIR="$(pwd)"

# Lista mínima de ficheros a comprobar
REQUIRED_FILES=(
  "app.py"
  "requirements.txt"
  "setup_local_lab.sh"
  "self_check.py"
  "ENTREGA.md"
  "core/uart_sim.py"
  "core/mqtt_sim.py"
  "core/fw_sim.py"
  "core/chain_sim_py.py"
  "pages/1_Amenazas_IoT.py"
  "pages/2_Firmware_y_Contraseñas.py"
  "pages/3_Blockchain_Seguridad.py"
  "pages/4_Auditoria_Entrega.py"
  "tests/test_uart.py"
  "tests/test_mqtt.py"
  "tests/test_fw.py"
  "tests/test_chain_py.py"
)

echo "== Verificando estructura del proyecto =="
missing=0
for f in "${REQUIRED_FILES[@]}"; do
  if [ ! -f "$ROOT_DIR/$f" ]; then
    echo "✖ Falta archivo: $f"
    missing=$((missing + 1))
  fi
done

if [ $missing -ne 0 ]; then
  echo
  echo "ERROR: faltan $missing archivo(s) requeridos."
  echo "Por favor crea o copia los archivos indicados antes de empaquetar."
  exit 1
fi

echo "✔ Todos los archivos requeridos existen."
echo

# Ejecutar el empaquetado
if [ ! -f "$ROOT_DIR/pack_for_students.py" ]; then
  echo "✖ No se encuentra pack_for_students.py en la raíz del proyecto."
  echo "Copia este script antes de continuar."
  exit 1
fi

echo "== Ejecutando empaquetado local =="
python3 "$ROOT_DIR/pack_for_students.py"

echo
echo "✅ Proceso completado. Busca el archivo 'iot-secure-app.zip' en:"
echo "   $ROOT_DIR"
echo
echo "Nota: este script es completamente local y no realiza llamadas de red."
