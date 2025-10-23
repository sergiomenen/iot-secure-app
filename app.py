# app.py — portada minimal para evitar errores de import
import streamlit as st

st.set_page_config(page_title="IoT Secure App", page_icon="🔒", layout="wide")

st.title("🔒 IoT Secure App (local-only)")
st.markdown("""
Bienvenido. Usa el menú lateral para navegar:

- **Amenazas IoT**: UART y MQTT simulados en memoria.
- **Blockchain Seguridad**: ledger append-only, control de acceso y actuador.
- **Auditoría Entrega**: exporta evidencias (JSON/CSV/checklist).

> Todo es local, sin llamadas de red ni descargas en tiempo de ejecución.
""")

st.info("Sugerencia: comienza por **Blockchain Seguridad** → *Iniciar cadena en memoria* y luego registra una lectura.")
