# core/uart_sim.py
# Simulador de interfaz UART lógica en memoria con un pequeño intérprete de comandos.
# No realiza llamadas externas: todo es local y determinista.

from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Tuple
import json
import hashlib
import time


@dataclass
class UARTState:
    """
    Estado de la UART simulada y del dispositivo "virtual".
    - secure: si True, operaciones sensibles requieren autenticación previa.
    - key_value: valor de una "clave" configurable via SET KEY=...
    - pw: contraseña de administración (para AUTH).
    - fail_count: contador de fallos consecutivos de AUTH.
    - locked: si True, el dispositivo está bloqueado para operaciones sensibles.
    """
    secure: bool = True
    key_value: str = "NONE"
    pw: str = "IoT-Password!"
    fail_count: int = 0
    locked: bool = True  # Arranca bloqueado hasta que se haga AUTH correcto.


# ------------------ Utilidades de serialización ------------------ #
def to_json(state: UARTState) -> str:
    """Serializa el estado a un JSON legible."""
    return json.dumps(asdict(state), ensure_ascii=False, sort_keys=True, indent=2)


def from_json(jsonstr: str) -> UARTState:
    """Reconstruye un UARTState desde JSON."""
    data = json.loads(jsonstr)
    # Valores por defecto si faltan campos
    return UARTState(
        secure=bool(data.get("secure", True)),
        key_value=str(data.get("key_value", "NONE")),
        pw=str(data.get("pw", "IoT-Password!")),
        fail_count=int(data.get("fail_count", 0)),
        locked=bool(data.get("locked", True)),
    )


# ------------------ Lógica de comandos ------------------ #
_HELP_TEXT = (
    "Comandos disponibles:\n"
    "  HELP                         -> muestra esta ayuda\n"
    "  STATUS                       -> estado del dispositivo\n"
    "  READ TEMP                    -> lee una temperatura simulada\n"
    "  DUMP SECRETS                 -> vuelca secretos (requiere autenticación si secure=ON)\n"
    "  SET KEY=<valor>              -> establece la clave (requiere autenticación si secure=ON)\n"
    "  AUTH <password>              -> autentica y desbloquea\n"
)

def _is_sensitive_allowed(state: UARTState) -> bool:
    """Determina si se permiten acciones sensibles (según modo y bloqueo)."""
    if not state.secure:
        return True
    return not state.locked


def _simulate_temp(state: UARTState) -> float:
    """
    Genera una lectura de temperatura determinista pero con ligera variación,
    sin depender de fuentes externas.
    """
    # Base derivada de key_value para que sea estable por clave
    base_hash = hashlib.sha256(state.key_value.encode("utf-8")).hexdigest()
    base = (int(base_hash[:4], 16) % 2000) / 100.0  # 0.00..20.00
    # Pequeña variación con el tiempo (segundos dentro del minuto)
    t = int(time.time()) % 60
    jitter = (t % 7) * 0.1  # 0.0..0.6
    # Rango razonable tipo 18.0..28.6
    return 18.0 + (base % 10.0) + jitter


def _status_text(state: UARTState) -> str:
    key_preview = hashlib.sha1(state.key_value.encode("utf-8")).hexdigest()[:8]
    return (
        "=== STATUS ===\n"
        f"secure: {'ON' if state.secure else 'OFF'}\n"
        f"locked: {'YES' if state.locked else 'NO'}\n"
        f"fail_count: {state.fail_count}\n"
        f"key_value: set (sha1[:8]={key_preview})\n"
        "=============="
    )


def handle_cmd(state: UARTState, cmd: str) -> str:
    """
    Procesa un comando textual y devuelve la respuesta.
    No modifica estado salvo para comandos que lo requieren.
    """
    if not isinstance(cmd, str):
        return "ERR: comando inválido"

    raw = cmd.strip()
    if not raw:
        return "ERR: vacío"

    upper = raw.upper()

    # HELP
    if upper == "HELP":
        return _HELP_TEXT

    # STATUS
    if upper == "STATUS":
        return _status_text(state)

    # READ TEMP
    if upper == "READ TEMP":
        temp = _simulate_temp(state)
        return f"TEMP={temp:.1f}C"

    # DUMP SECRETS
    if upper == "DUMP SECRETS":
        if not _is_sensitive_allowed(state):
            return "ERROR: acceso denegado (locked/secure)"
        # Mostrar secretos completos (es una simulación educativa)
        return (
            "=== SECRETS ===\n"
            f"KEY_VALUE: {state.key_value}\n"
            f"ADMIN_PW:  {state.pw}\n"
            "================"
        )

    # SET KEY=<v>
    if upper.startswith("SET KEY="):
        if not _is_sensitive_allowed(state):
            return "ERROR: acceso denegado (locked/secure)"
        # Extraer después de '=' respetando mayúsculas/minúsculas del valor original
        try:
            value = raw.split("=", 1)[1]
        except IndexError:
            return "ERR: uso: SET KEY=<valor>"
        state.key_value = value
        return "OK: KEY actualizado"

    # AUTH <pass>
    if upper.startswith("AUTH "):
        # Respetar el valor original del password tras el espacio
        _, _, provided = raw.partition(" ")
        provided = provided.strip()
        if provided == "":
            return "ERR: uso: AUTH <password>"

        if state.locked and provided == state.pw:
            state.locked = False
            state.fail_count = 0
            return "OK: autenticado, dispositivo DESBLOQUEADO"
        else:
            # fallo (si ya estaba desbloqueado y pw no coincide, no cambia locked)
            if state.locked:
                state.fail_count += 1
                if state.fail_count >= 3:
                    state.locked = True  # ya lo está, pero lo explicitamos
                    return "ERROR: autenticación fallida (lockout)"
            return "ERROR: autenticación fallida"

    # Comando no reconocido
    return "ERR: comando desconocido (usa HELP)"


# ------------------ Mini-demo local ------------------ #
if __name__ == "__main__":
    st = UARTState()
    print("UART DEMO :: inicio")
    print(handle_cmd(st, "HELP"))
    print(handle_cmd(st, "STATUS"))
    print("-- Intento DUMP SECRETS sin auth --")
    print(handle_cmd(st, "DUMP SECRETS"))
    print("-- AUTH incorrecto x2 --")
    print(handle_cmd(st, "AUTH badpass"))
    print(handle_cmd(st, "AUTH 1234"))  # probablemente mal si pw por defecto es IoT-Password!
    print("-- AUTH correcto --")
    print(handle_cmd(st, f"AUTH {st.pw}"))
    print(handle_cmd(st, "SET KEY=DEMO-KEY-001"))
    print(handle_cmd(st, "READ TEMP"))
    print(handle_cmd(st, "DUMP SECRETS"))
    print("-- Serialización --")
    js = to_json(st)
    print(js)
    print("-- Restaurar y STATUS --")
    st2 = from_json(js)
    print(handle_cmd(st2, "STATUS"))
