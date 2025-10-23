# App principal de Streamlit: panel de demostración local de UART/MQTT simulados, seguridad de firmware y bitácora tipo blockchain.
import streamlit as st
from core.uart_sim import UARTState, handle_cmd
from core.mqtt_sim import BrokerMem, publish, subscribe, sniff, spoof, mitm_publish
from core.fw_sim import FirmwareSecurity
from core.chain_sim_py import ChainSim

st.set_page_config(page_title="IoT Secure App", page_icon="🔒", layout="wide")

# Estado inicial
if "uart" not in st.session_state:
    st.session_state.uart = UARTSim()
if "broker" not in st.session_state:
    st.session_state.broker = LocalBroker()
if "mqtt_client" not in st.session_state:
    st.session_state.mqtt_client = MQTTClientSim(st.session_state.broker, client_id="ui")
if "fwsec" not in st.session_state:
    st.session_state.fwsec = FirmwareSecurity()
if "chain" not in st.session_state:
    st.session_state.chain = ChainSim()

st.title("🔒 IoT Secure App (local-only)")
st.markdown(
    """
Esta app demuestra **conceptos de seguridad IoT** sin conexión: simulación de UART/MQTT,
verificación de firmware (hash y cifrado local) y una bitácora encadenada estilo *blockchain*.
"""
)

tab1, tab2, tab3, tab4 = st.tabs(["UART", "MQTT", "Firmware", "Bitácora"])

with tab1:
    st.subheader("Simulador UART")
    col_a, col_b = st.columns(2)
    with col_a:
        tx = st.text_area("Datos a enviar por UART", value="HELLO-IOT")
        if st.button("Transmitir ➜"):
            st.session_state.uart.write(tx)
            st.success("Transmitido al buffer UART.")
    with col_b:
        n = st.number_input("Bytes a leer (0 = todo)", min_value=0, step=1, value=0)
        if st.button("Leer ⬇"):
            out = st.session_state.uart.read(None if n == 0 else n)
            st.code(out or "", language="text")
    st.caption("La UART simulada solo usa memoria local (sin dispositivos reales).")

with tab2:
    st.subheader("Simulador MQTT (local-only)")
    topic = st.text_input("Topic", value="demo/telemetry")
    msg = st.text_input("Mensaje", value="temp=21.5C")
    if "mqtt_msgs" not in st.session_state:
        st.session_state.mqtt_msgs = []

    def on_msg(t, m):
        st.session_state.mqtt_msgs.append((t, m))

    # (Re)registrar la suscripción cada render para asegurar el callback
    st.session_state.mqtt_client.subscribe(topic, on_msg)

    c1, c2 = st.columns(2)
    with c1:
        if st.button("Publicar"):
            st.session_state.mqtt_client.publish(topic, msg)
            st.success("Publicado en el broker local.")
    with c2:
        if st.button("Limpiar mensajes"):
            st.session_state.mqtt_msgs = []

    st.write("📨 Mensajes recibidos (solo en memoria):")
    for t, m in st.session_state.mqtt_msgs[-50:]:
        st.code(f"{t}: {m}")

with tab3:
    st.subheader("Seguridad de firmware (hash + cifrado local)")
    fw = st.text_area("Contenido de firmware (texto o hex)", value="print('v1.0')")
    c1, c2, c3 = st.columns(3)
    with c1:
        if st.button("Calcular SHA-256"):
            st.code(st.session_state.fwsec.hash_firmware(fw), language="text")
    with c2:
        pwd = st.text_input("Contraseña para cifrar", type="password", value="DemoPass_123")
        if st.button("Cifrar con clave derivada"):
            token = st.session_state.fwsec.encrypt_with_password(fw, pwd)
            st.session_state.last_token = token
            st.code(token)
    with c3:
        pwd2 = st.text_input("Contraseña para descifrar", type="password", value="DemoPass_123", key="pwd2")
        if st.button("Descifrar último token"):
            token = st.session_state.get("last_token", "")
            if not token:
                st.warning("No hay token disponible; primero cifra algo.")
            else:
                try:
                    plain = st.session_state.fwsec.decrypt_with_password(token, pwd2)
                    st.code(plain)
                except Exception as e:
                    st.error(f"Error al descifrar: {e}")

    st.markdown("**Chequeo de contraseña:**")
    cand = st.text_input("Probar contraseña", value="DemoPass_123", key="pwdchk")
    ok, hints = st.session_state.fwsec.password_ok(cand)
    st.write("Resultado:", "✅ Fuerte" if ok else "⚠️ Débil")
    if hints:
        st.write("Sugerencias:", ", ".join(hints))

with tab4:
    st.subheader("Bitácora encadenada (tipo blockchain)")
    event = st.text_input("Nuevo evento", value="Arranque del dispositivo")
    if st.button("Añadir bloque"):
        st.session_state.chain.add(event)
        st.success("Evento añadido a la cadena local.")
    valid = st.session_state.chain.is_valid()
    st.write("Integridad de la cadena:", "✅ Válida" if valid else "❌ Rota")
    st.json([b.to_dict() for b in st.session_state.chain.chain])

st.info("Navega a la carpeta **pages/** para contenidos didácticos por tema.")
