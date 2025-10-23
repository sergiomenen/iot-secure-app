# pages/1_Amenazas_IoT.py
# Página educativa: demostraciones locales de amenazas comunes en IoT usando simuladores en memoria.
# Usa únicamente los módulos locales core.uart_sim y core.mqtt_sim (sin red ni sockets).

import streamlit as st
import json
from core.uart_sim import UARTState, handle_cmd, to_json, from_json
from core.mqtt_sim import BrokerMem, sniff, spoof, mitm_publish

st.set_page_config(page_title="Amenazas IoT", page_icon="🛡️")

st.title("🔍 Amenazas IoT — Demo local (sin red)")
st.markdown(
    "Esta página muestra ejemplos prácticos y locales de vectores de ataque típicos en IoT: "
    "interfaces de depuración (UART) y manipulación de mensajes (MQTT). "
    "Todo ejecutado **en memoria** con simuladores: no hay conexiones de red ni llamadas externas."
)

# -------------------------
# Inicializar estado UART
# -------------------------
if "uart_state" not in st.session_state:
    # estado por defecto: secure ON y locked True (según core/uart_sim.UARTState)
    st.session_state.uart_state = UARTState()

st.header("1) Interfaz UART (simulada)")
st.markdown(
    "La interfaz UART suele exponer funciones de depuración y administración. "
    "En esta demo puedes alternar el modo seguro y enviar comandos al intérprete UART local."
)

col_uart_top, col_uart_side = st.columns([3, 1])

with col_uart_side:
    modo_seguro = st.checkbox("Modo seguro (secure)", value=st.session_state.uart_state.secure)
    # sincronizar el flag secure del estado
    st.session_state.uart_state.secure = bool(modo_seguro)
    st.write("Estado bloqueo:", "🔒 Bloqueado" if st.session_state.uart_state.locked else "🔓 Desbloqueado")

with col_uart_top:
    cmd_input = st.text_input("Comando UART (ej.: HELP | STATUS | READ TEMP | AUTH <pass> | DUMP SECRETS | SET KEY=VAL)", value="HELP")
    send = st.button("Enviar comando UART")

if send:
    out = handle_cmd(st.session_state.uart_state, cmd_input)
    # mostrar salida y estado actualizado
    st.subheader("Respuesta UART")
    st.code(out, language="text")
    st.experimental_rerun()  # re-render para actualizar lock/secure display

# Mostrar estado serializado (útil para inspección didáctica)
with st.expander("Mostrar estado UART (JSON)"):
    try:
        st.code(to_json(st.session_state.uart_state), language="json")
    except Exception:
        st.write("No se pudo serializar el estado UART.")

st.markdown(
    "**Qué observar:**\n\n"
    "- Si `secure` está activo y el dispositivo está `locked`, comandos sensibles como `DUMP SECRETS` o `SET KEY=` deben fallar.\n"
    "- Usa `AUTH <password>` para desbloquear según la contraseña almacenada (educativa: no emplees contraseñas por defecto en dispositivos reales).\n"
    "- Observa cómo la exposición de interfaces como UART puede revelar secretos si no están protegidas."
)

st.markdown("---")

# -------------------------
# Inicializar broker MQTT
# -------------------------
if "broker_mem" not in st.session_state:
    st.session_state.broker_mem = BrokerMem(maxlen=200)

st.header("2) Broker MQTT (simulado en memoria)")
st.markdown(
    "El broker aquí está en memoria: `publish` almacena mensajes en colas por topic. "
    "Mostramos también técnicas de manipulación locales: **spoof** (inyección) y **MITM publish** (modificación)."
)

col1, col2 = st.columns(2)

with col1:
    topic = st.text_input("Topic", value="demo/telemetry")
    payload_text = st.text_area("Payload (JSON o texto)", value='{"temp": 21.5}')
    # intentar parsear payload como JSON si es posible
    try:
        payload_obj = json.loads(payload_text)
    except Exception:
        payload_obj = payload_text

    if st.button("Publicar (publish)"):
        st.session_state.broker_mem.publish(topic, payload_obj)
        st.success(f"Publicado en topic '{topic}' (broker local).")

    if st.button("Spoof (inyectar mensaje falso)"):
        spoofed = spoof(st.session_state.broker_mem, topic, payload_obj)
        st.success(f"Mensaje spoof inyectado (ts={spoofed.timestamp:.1f}).")

with col2:
    if st.button("MITM publish (modifica payload antes de guardar)"):
        mitm_msg = mitm_publish(st.session_state.broker_mem, topic, payload_obj)
        st.success(f"MITM aplicado y mensaje almacenado (ts={mitm_msg.timestamp:.1f}).")

    st.write("Nota: `Spoof` inyecta un mensaje como si viniera de un publicador legítimo; "
             "`MITM publish` modifica el payload antes de almacenarlo en el broker (simula intervención).")

st.markdown("### Sniffer local (leer últimos mensajes de la cola)")
sniff_topic = st.text_input("Topic a espiar (sniffer)", value=topic, key="sniff_topic")
n_msgs = st.number_input("Últimos N mensajes", min_value=1, max_value=200, value=5, step=1, key="sniff_n")

if st.button("Actualizar sniffer"):
    q = st.session_state.broker_mem.subscribe(sniff_topic)
    msgs = sniff(q, maxn=int(n_msgs))
    st.subheader(f"Últimos {len(msgs)} mensajes en '{sniff_topic}'")
    if not msgs:
        st.info("No hay mensajes en ese topic (aún).")
    else:
        # mostrar en tabla simple
        for m in msgs:
            ts = m.get("ts")
            payload = m.get("payload")
            st.write(f"- [{ts:.1f}] — {payload}")

st.markdown(
    "**Qué observar:**\n\n"
    "- Un atacante puede *inyectar* (spoof) mensajes si puede publicar en el broker; esto puede falsear telemetrías.\n"
    "- Un MITM puede alterar el contenido de mensajes antes de que los consumidores los procesen.\n"
    "- En escenarios reales usar autenticación por cliente, firmas de mensajes y TLS para mitigar estas amenazas."
)

st.markdown("---")
st.caption("Todos los simuladores aquí son locales y en memoria (no usan sockets ni conexiones externas).")
