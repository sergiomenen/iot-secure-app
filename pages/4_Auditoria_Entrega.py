# pages/4_Auditoria_Entrega.py
# Página de auditoría y generación de paquete de entrega.
# Lee el ledger desde st.session_state (si existe), muestra entradas y eventos,
# y permite descargar audit.json, entries.csv, events.csv y checklist.txt.
# Todo en memoria (no se crean archivos en disco ni se realizan llamadas de red).

import streamlit as st
import json
import csv
import io
from dataclasses import asdict
from typing import List, Dict, Any

from core.chain_sim_py import Ledger

st.set_page_config(page_title="Auditoría y Entrega", page_icon="📦")

st.title("📦 Auditoría y Entrega")
st.markdown(
    "Revisa y exporta la evidencia local desde el ledger en sesión. "
    "Si no has iniciado el ledger en la página de *Blockchain y Seguridad*, vuelve allí y pulsa 'Iniciar cadena en memoria'."
)

if "ledger" not in st.session_state:
    st.warning("No se encuentra un ledger en session_state. Ve a la página de 'Blockchain y Seguridad' y pulsa 'Iniciar cadena en memoria'.")
    st.stop()

ledger: Ledger = st.session_state.ledger

# ---------- Mostrar entradas y eventos ----------
st.header("Entradas registradas (ledger)")
entries = ledger.all_entries()
if not entries:
    st.info("No hay entradas registradas.")
else:
    # Convertir para mostrar
    entries_display: List[Dict[str, Any]] = [asdict(e) for e in entries]
    st.json(entries_display)

st.markdown("---")
st.header("Eventos (auditoría)")
events = ledger.get_events()
if not events:
    st.info("No hay eventos registrados.")
else:
    events_display: List[Dict[str, Any]] = [asdict(ev) for ev in events]
    st.json(events_display)

st.markdown("---")

# ---------- Generar audit.json (en memoria) ----------
st.header("Exportar paquete de auditoría (en memoria)")

def build_audit_json(ledger_obj: Ledger) -> str:
    payload = {
        "entries": [asdict(e) for e in ledger_obj.all_entries()],
        "events": [asdict(ev) for ev in ledger_obj.get_events()],
        "meta": {
            "exported_by": "streamlit_session",
            "notes": "Export generado localmente desde la app; contiene entradas y eventos actuales en memoria."
        }
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)

audit_json_str = build_audit_json(ledger)

st.subheader("Vista previa audit.json")
st.code(audit_json_str[:2000] + ("\n... (truncado)" if len(audit_json_str) > 2000 else ""), language="json")

st.download_button(
    label="Descargar audit.json",
    data=audit_json_str.encode("utf-8"),
    file_name="audit.json",
    mime="application/json"
)

# ---------- Generar entries.csv y events.csv en memoria ----------
def build_entries_csv(entries_list: List[Any]) -> str:
    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(["id", "submitter", "timestamp", "data_hex", "pointer"])
    for e in entries_list:
        writer.writerow([e.id, e.submitter, e.timestamp, e.data_hex, e.pointer or ""])
    return si.getvalue()

def build_events_csv(events_list: List[Any]) -> str:
    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(["id", "timestamp", "kind", "metadata_json"])
    for ev in events_list:
        writer.writerow([ev.id, ev.timestamp, ev.kind, json.dumps(ev.metadata, ensure_ascii=False)])
    return si.getvalue()

entries_csv_str = build_entries_csv(entries)
events_csv_str = build_events_csv(events)

col1, col2 = st.columns(2)
with col1:
    st.download_button(
        label="Descargar entries.csv",
        data=entries_csv_str.encode("utf-8"),
        file_name="entries.csv",
        mime="text/csv"
    )
with col2:
    st.download_button(
        label="Descargar events.csv",
        data=events_csv_str.encode("utf-8"),
        file_name="events.csv",
        mime="text/csv"
    )

st.markdown("---")

# ---------- Checklist.txt (texto plano) ----------
st.header("Checklist de entrega")
checklist_lines = [
    "Checklist de entrega - ejercicio IoT Secure App",
    "",
    "1) Hash del firmware de ejemplo y token cifrado (si aplica).",
    "2) JSON de la bitácora encadenada con >= 2 eventos (audit.json).",
    "3) entries.csv y events.csv exportados desde la app (auditoría).",
    "4) Nota breve describiendo mejoras propuestas a contraseñas débiles.",
    "5) Capturas o JSON de la sesión con pruebas de OTA firmada (si se realizó).",
    "",
    "Instrucciones: incluir audit.json, entries.csv, events.csv y una nota breve en la entrega."
]
checklist_text = "\n".join(checklist_lines)

st.text_area("Checklist (puedes editar antes de descargar)", value=checklist_text, height=200, key="checklist_area")

st.download_button(
    label="Descargar checklist.txt",
    data=st.session_state.get("checklist_area", checklist_text).encode("utf-8"),
    file_name="checklist.txt",
    mime="text/plain"
)

st.markdown("---")

st.caption(
    "Todos los ficheros se generan en memoria desde los objetos en session_state y se descargan localmente desde tu navegador. "
    "La app no sube nada a la red ni escribe archivos en el servidor."
)
