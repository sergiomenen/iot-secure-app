# pages/2_Firmware_y_Contraseñas.py
# Página de prácticas: gestión de DeviceState, primer arranque y flujo OTA con firma RSA en memoria.
# Usa únicamente core.fw_sim (todo offline, sin red).

import streamlit as st
import json
from dataclasses import asdict
from core.fw_sim import (
    DeviceState,
    attack_default_creds,
    first_boot,
    verify_login,
    gen_keys,
    sign_image,
    verify_image,
)

st.set_page_config(page_title="Firmware y Contraseñas", page_icon="🔐")

st.title("🧩 Firmware y Contraseñas")
st.markdown(
    "Práctica local: inspecciona el estado del dispositivo, realiza el primer arranque (hardening), "
    "y simula un proceso OTA firmado totalmente en memoria."
)

# ----------------------
# Inicializar DeviceState en la sesión
# ----------------------
if "device_state" not in st.session_state:
    st.session_state.device_state = DeviceState()

ds: DeviceState = st.session_state.device_state

st.subheader("Estado del dispositivo")
with st.expander("Mostrar DeviceState"):
    try:
        # mostrar la mayor parte del estado; truncar hashes largos por legibilidad
        d = asdict(ds)
        if d.get("admin_hash"):
            d["admin_hash"] = d["admin_hash"][:16] + "..."  # truncar
        if isinstance(d.get("firmware"), (bytes, bytearray)):
            d["firmware"] = f"<{len(d['firmware'])} bytes>"
        st.json(d)
    except Exception as e:
        st.write("No se puede serializar DeviceState:", e)

# ----------------------
# Test credenciales por defecto
# ----------------------
st.markdown("### Comprobar credenciales por defecto")
if st.button("Probar admin/admin"):
    vuln = attack_default_creds(ds)
    if vuln:
        st.error("Vulnerable: credenciales por defecto detectadas (admin/admin).")
    else:
        st.success("No vulnerable a admin/admin (contraseña cambiada o se detectó hash distinto).")

# ----------------------
# Primer arranque (first boot)
# ----------------------
st.markdown("### Primer arranque (setup) — reemplaza contraseña en texto por hash")
with st.form("first_boot_form"):
    new_pass = st.text_input("Nueva contraseña de administrador (primera vez)", type="password", value="")
    submitted = st.form_submit_button("Aplicar primer arranque (first_boot)")
    if submitted:
        if not new_pass:
            st.warning("Introduce una contraseña no vacía.")
        else:
            try:
                first_boot(ds, new_pass)
                st.success("First boot aplicado: contraseña hasheada y password en texto borrada.")
            except Exception as exc:
                st.error(f"Error en first_boot: {exc}")

# ----------------------
# Verificar login (opcional)
# ----------------------
st.markdown("### Verificar login (test)")
with st.expander("Probar credenciales de administrador"):
    user = st.text_input("Usuario", value=ds.admin_user, key="verify_user")
    pwd = st.text_input("Password a verificar", type="password", key="verify_pwd")
    if st.button("Verificar login"):
        ok = verify_login(ds, user, pwd)
        if ok:
            st.success("Credenciales válidas.")
        else:
            st.error("Credenciales inválidas.")

# ----------------------
# OTA: generar claves, firmar imagen y verificar
# ----------------------
st.markdown("### OTA simulado: firmar imagen y verificar antes de aplicar")
if "ota_priv_pem" not in st.session_state:
    st.session_state.ota_priv_pem = None
    st.session_state.ota_pub_pem = None
    st.session_state.ota_signature = None
    st.session_state.ota_image = None

col_a, col_b = st.columns(2)

with col_a:
    if st.button("Generar par de claves RSA (en memoria)"):
        priv_pem, pub_pem = gen_keys()
        st.session_state.ota_priv_pem = priv_pem
        st.session_state.ota_pub_pem = pub_pem
        st.success("Claves RSA generadas en memoria (priv/pub almacenadas en session_state).")
        st.code(pub_pem.decode("utf-8").splitlines()[0], language="text")

with col_b:
    if st.session_state.get("ota_pub_pem"):
        st.write("Clave pública disponible (truncada):")
        st.code(st.session_state.ota_pub_pem.decode("utf-8").splitlines()[0])
    else:
        st.info("Aún no hay claves RSA generadas.")

st.markdown("Sube o escribe la 'imagen' de firmware (texto) que quieres firmar:")
image_text = st.text_area("Contenido de imagen (texto)", value="print('firmware v1.0')", height=120)
if st.button("Firmar imagen con clave privada (sign_image)"):
    if not st.session_state.get("ota_priv_pem"):
        st.error("Primero genera un par de claves RSA.")
    else:
        img_bytes = image_text.encode("utf-8")
        sig = sign_image(st.session_state.ota_priv_pem, img_bytes)
        st.session_state.ota_signature = sig
        st.session_state.ota_image = img_bytes
        st.success("Imagen firmada en memoria (firma almacenada en session_state).")
        st.write(f"Firma longitud: {len(sig)} bytes")

st.markdown("Verificación de la firma (verify_image):")
if st.button("Verificar firma y aplicar OTA si OK"):
    if not st.session_state.get("ota_pub_pem") or not st.session_state.get("ota_signature") or not st.session_state.get("ota_image"):
        st.error("Falta clave pública, firma o imagen. Asegúrate de haber generado y firmado la imagen.")
    else:
        pub = st.session_state.ota_pub_pem
        sig = st.session_state.ota_signature
        img = st.session_state.ota_image
        verified = verify_image(pub, img, sig)
        if verified:
            # simular aplicar OTA: actualizar firmware bytes y ota_version
            ds.firmware = img
            # incrementar ota_version sencillamente
            try:
                major, minor, patch = ds.ota_version.split(".")
                new_version = f"{major}.{minor}.{int(patch)+1}"
            except Exception:
                new_version = "1.0.0"
            ds.ota_version = new_version
            st.success(f"Firma verificada. OTA aplicada. nueva ota_version={ds.ota_version}")
        else:
            st.error("Firma inválida: NO aplicar OTA.")

# Mostrar info de firma/imagen en sesión
with st.expander("Estado OTA en sesión"):
    st.write("Privada en session_state:", "✅" if st.session_state.get("ota_priv_pem") else "❌")
    st.write("Pública en session_state:", "✅" if st.session_state.get("ota_pub_pem") else "❌")
    st.write("Imagen firmada en session_state:", "✅" if st.session_state.get("ota_image") else "❌")
    st.write("Firma en session_state:", "✅" if st.session_state.get("ota_signature") else "❌")
    if st.session_state.get("ota_image"):
        st.write("Imagen (texto):")
        st.code(st.session_state.get("ota_image").decode("utf-8"))

st.markdown("---")

st.subheader("Mitigaciones y buenas prácticas (resumen)")
st.write(
    "- No dejar credenciales por defecto (admin/admin). Ejecutar `first_boot` para rotar y hashear contraseñas.\n"
    "- Almacenar solo hashes de contraseñas (preferible con sal y KDF en entornos reales).\n"
    "- Firmar las imágenes de firmware con claves privadas seguras; verificar firma antes de aplicar OTA.\n"
    "- Mantener las claves privadas protegidas (hardware secure element cuando sea posible) y no incrustarlas en dispositivos sin protección.\n"
)

st.caption("Esta página es una simulación educativa local: no realiza llamadas de red ni guarda claves en servidores.")
