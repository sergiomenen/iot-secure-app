#!/usr/bin/env python3
"""
pack_for_students.py

Empaqueta el proyecto actual en un zip "iot-secure-app.zip" tras verificar
que los ficheros principales del scaffold existen.

Uso:
  python pack_for_students.py
  python pack_for_students.py --out mypack.zip

Notas:
- No realiza llamadas de red.
- Excluye carpetas de entorno/artefactos (p. ej., .venv, __pycache__, .git, .pytest_cache, .DS_Store).
"""

from __future__ import annotations
import argparse
import sys
import os
from pathlib import Path
import zipfile
from typing import List, Set


# --- Configuración de archivos requeridos (scaffold mínimo) ---
REQUIRED_FILES: List[str] = [
    "requirements.txt",
    "app.py",
    "ENTREGA.md",
    "setup_local_lab.sh",
    "self_check.py",
    # core/
    "core/uart_sim.py",
    "core/mqtt_sim.py",
    "core/fw_sim.py",
    "core/chain_sim_py.py",
    # pages/
    "pages/1_Amenazas_IoT.py",
    "pages/2_Firmware_y_Contraseñas.py",
    "pages/3_Blockchain_Seguridad.py",
    "pages/4_Auditoria_Entrega.py",
    # tests/
    "tests/test_uart.py",
    "tests/test_mqtt.py",
    "tests/test_fw.py",
    "tests/test_chain_py.py",
]

# Directorios/archivos a excluir al crear el zip
EXCLUDE_DIRS: Set[str] = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".idea",
    ".vscode",
    "build",
    "dist",
    ".mypy_cache",
    ".ruff_cache",
}
EXCLUDE_FILE_PATTERNS: List[str] = [
    ".DS_Store",
    "*.pyc",
    "*.pyo",
    "*.log",
    "*.tmp",
]


def matches_pattern(filename: str, patterns: List[str]) -> bool:
    import fnmatch
    for pat in patterns:
        if fnmatch.fnmatch(filename, pat):
            return True
    return False


def verify_required_files(root: Path, required: List[str]) -> List[str]:
    missing: List[str] = []
    for rel in required:
        p = root / rel
        if not p.exists():
            missing.append(rel)
    return missing


def create_zip(root: Path, out_path: Path) -> None:
    # Eliminar zip previo si existe
    if out_path.exists():
        out_path.unlink()

    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for dirpath, dirnames, filenames in os.walk(root):
            # Normalizar y filtrar directorios excluidos
            rel_dir = Path(dirpath).relative_to(root)

            # Modificar dirnames IN-PLACE para que os.walk no entre
            dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]

            for fname in filenames:
                # Excluir por patrón
                if matches_pattern(fname, EXCLUDE_FILE_PATTERNS):
                    continue

                abs_file = Path(dirpath) / fname
                # No incluir el propio zip si se ejecuta en la raíz
                if abs_file.resolve() == out_path.resolve():
                    continue

                rel_file = rel_dir / fname
                # Añadir al zip con ruta relativa
                zf.write(abs_file, arcname=str(rel_file))


def main() -> int:
    parser = argparse.ArgumentParser(description="Empaqueta el proyecto en iot-secure-app.zip verificando archivos requeridos.")
    parser.add_argument("--out", default="iot-secure-app.zip", help="Nombre del archivo zip de salida (por defecto: iot-secure-app.zip)")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent  # asumir que se ejecuta desde la raíz del proyecto o dentro de ella
    # Si el script está dentro de la raíz, usamos esa raíz. Si se ejecuta desde otro sitio, ajustar:
    # Intentar detectar si existe 'app.py' en el cwd; si sí, usar cwd.
    cwd = Path.cwd()
    if (cwd / "app.py").exists() and (cwd / "core").exists():
        root = cwd

    # 1) Verificar ficheros requeridos
    missing = verify_required_files(root, REQUIRED_FILES)
    if missing:
        print("✖ FALTAN archivos requeridos del scaffold:\n")
        for m in missing:
            print(f"  - {m}")
        print("\nSolución: crea/pega los ficheros listados en las rutas indicadas y vuelve a ejecutar.")
        return 2

    # 2) Crear zip
    out_path = (root / args.out).resolve()
    try:
        create_zip(root, out_path)
    except Exception as e:
        print(f"✖ Error al crear el ZIP: {e}")
        return 3

    print("✔ Paquete creado correctamente.")
    print(f"Ruta del ZIP: {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
