# pages/3_Blockchain_Seguridad.py
# Página: ledger en memoria + control de acceso + actuador (todo local-only, sin red).
# Usa core.chain_sim_py: Ledger, AccessControlPy, ActuatorPy

import streamlit as st
import json
import time
import hashlib
from dataclasses import asdict

from core.chain_sim_py import Ledger, AccessControlPy, ActuatorPy

st.set_page_config(page_title="Blockchain y Seguridad", page_icon="⛓️")

st.title("⛓️ Blockchain aplicada a seguridad (simulación local)")
st.markdown(
    "Esta página crea un *ledger* append-only en memoria y demuestra registro de lecturas, "
    "control de acceso temporal y un actuador que verifica permisos antes de actuar. "
    "Todo es local: no se usa red ni servicios externos."
)

# -----------------------
# Inicializar / Iniciar estructura
# -----------------------
if "ledger" not in st.session_state or "ac" not in st.session_state or "actuator" not in st.session_state:
    st.info("Pulsa 'Iniciar cadena en memoria' para crear Ledger, AccessControl y Actuator en session_state.")
else:
    st.success("Ledger / AccessControl / Actuator en memoria listos.")

if st.button("Iniciar cadena en memoria"):
    st.session_state.ledger = Ledger()
    # por defecto añadir un admin conocido para poder conceder permisos desde la UI
    st.session_state.ac = AccessControlPy(initial_admins=["admin"])
    st.session_state.actuator = ActuatorPy(st.session_state.ledger, st.session_state.ac)
    st.success("Ledger, AccessControl (admin='admin') y Actuator creados en sesión.")

# helper to ensure components exist
def _ensure_components():
    if "ledger" not in st.session_state:
        st.error("Ledger no inicializado. Pulsa 'Iniciar cadena en memoria'.")
        st.stop()
    if "ac" not in st.session_state:
        st.error("AccessControl no inicializado. Pulsa 'Iniciar cadena en memoria'.")
        st.stop()
    if "actuator" not in st.session_state:
        st.error("Actuator no inicializado. Pulsa 'Iniciar cadena en memoria'.")
        st.stop()
    return st.session_state.ledger, st.session_state.ac, st.session_state.actuator

st.markdown("---")

# -----------------------
# Formulario para crear lectura (device, temp) -> register
# -----------------------
st.header("Registrar lectura (append-only)")
with st.form("register_form"):
    device = st.text_input("Device ID (submitter)", value="sensor1")
    temp = st.text_input("Temperatura (ej.: 22.5)", value="22.5")
    pointer = st.text_input("Pointer (opcional, p. ej. sensor:seq:0001)", value=f"{device}:seq:{int(time.time())}")
    submitted = st.form_submit_button("Registrar lectura en ledger")

if submitted:
    ledger, ac, actuator = _ensure_components()
    # Construir payload compactado JSON
    data_obj = {"device": device, "temp": temp, "ts": int(time.time())}
    data_compact = json.dumps(data_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    # Registrar en ledger
    entry_id = ledger.register(submitter=device, data_bytes=data_compact, pointer=pointer or None)
    local_hash = hashlib.sha256(data_compact).hexdigest()
    st.success("Lectura registrada en ledger (append-only).")
    st.write("Entry ID (ledger):", entry_id)
    st.write("Hash local del payload (SHA-256):", local_hash)
    st.caption("El entry_id es una huella generada por el ledger sobre submitter|timestamp|data|pointer; "
               "el hash local es SHA-256 del payload que has enviado.")

st.markdown("---")

# -----------------------
# Mostrar lista de entradas registradas
# -----------------------
st.header("Entradas registradas en el ledger")
if "ledger" in st.session_state:
    ledger = st.session_state.ledger
    entries = [asdict(e) for e in ledger.all_entries()]
    if not entries:
        st.info("No hay entradas registradas aún.")
    else:
        st.json(entries)
else:
    st.info("Ledger no iniciado todavía.")

st.markdown("---")

# -----------------------
# Grant / Actuate UI
# -----------------------
st.header("Control de acceso y actuación")
st.markdown("Concede permisos temporales y prueba el actuador que verifica acceso antes de actuar.")

col_g1, col_g2, col_g3 = st.columns(3)
with col_g1:
    resource = st.text_input("Resource (ej.: door1, relayA)", value="door1", key="resource_input")
with col_g2:
    gateway = st.text_input("Grant to (principal)", value="bob", key="gateway_input")
with col_g3:
    valid_secs = st.number_input("Valid seconds", min_value=1, value=60, step=1, key="valid_secs_input")

caller = st.text_input("Caller (admin que realiza grant / quien actúa)", value="admin", help="Debe ser admin para grant; para actuar usa el principal al que se le concedió permiso.")

grant_clicked = st.button("Grant permiso")
if grant_clicked:
    ledger, ac, actuator = _ensure_components()
    try:
        ac.grant(resource=resource, to=gateway, valid_seconds=int(valid_secs), caller=caller)
        # emitimos un evento explicito en ledger para auditoría
        ledger.emit_event("GrantApplied", {"resource": resource, "to": gateway, "valid_secs": int(valid_secs), "by": caller})
        st.success(f"Permiso otorgado: {gateway} -> {resource} por {valid_secs}s (caller={caller})")
    except Exception as e:
        st.error(f"Error al aplicar grant: {e}")

actuate_clicked = st.button("Actuar (Actuator.actuate)")
if actuate_clicked:
    ledger, ac, actuator = _ensure_components()
    # el actuador verificará acceso y lanzará PermissionError si no tiene
    try:
        ev = actuator.actuate(resource=resource, caller=caller)
        st.success(f"Actuación permitida. Evento emitido: {ev.kind} (id={ev.id})")
    except PermissionError as pe:
        st.error(f"Acción denegada: {pe}")

st.markdown(
    "Nota: el `caller` usado en Actuate es la identidad que intenta accionar el recurso. "
    "Si deseas simular que 'bob' actúa, pon `caller=bob` y pulsa 'Actuar'."
)

st.markdown("---")

# -----------------------
# Mostrar eventos
# -----------------------
st.header("Eventos del ledger (auditoría)")
if "ledger" in st.session_state:
    ledger = st.session_state.ledger
    evs = [asdict(ev) for ev in ledger.get_events()]
    if not evs:
        st.info("No hay eventos aún.")
    else:
        st.json(evs)
else:
    st.info("Ledger no iniciado todavía.")

st.markdown("---")
st.caption("Todo el sistema aquí es una simulación educativa en memoria. "
           "En entornos reales, la integridad de auditoría requiere almacenamiento inmutable, firmas y transmisión segura.")
