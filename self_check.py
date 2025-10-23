#!/usr/bin/env python3
"""
self_check.py

Script de auto-comprobación para los alumnos del laboratorio "iot-secure-app".
Ejecutar con: python self_check.py

Comprueba de forma local y offline los componentes principales en core/:
- Ledger / AccessControl / Actuator
- UART simulator (modo seguro / insecure)
- Firmware utilities (first_boot, sign/verify OTA)

Imprime un resumen con ✔ para OK y ✖ para fallo, más mensajes explicativos.
"""
from __future__ import annotations
import sys
import traceback
import json
import hashlib

# Importar módulos del proyecto (core/*)
try:
    from core.chain_sim_py import Ledger, AccessControlPy, ActuatorPy
    from core.uart_sim import UARTState, handle_cmd
    from core.fw_sim import DeviceState, attack_default_creds, first_boot, gen_keys, sign_image, verify_image
    from core.mqtt_sim import BrokerMem, sniff, spoof, mitm_publish
except Exception as e:
    print("ERROR: No se pudieron importar los módulos core/. Asegúrate de ejecutar desde la raíz del proyecto.")
    print("Detalle:", e)
    sys.exit(2)


CHECK_OK = "✔"
CHECK_FAIL = "✖"


def ok(msg: str):
    print(f"{CHECK_OK} {msg}")


def fail(msg: str):
    print(f"{CHECK_FAIL} {msg}")


def section(title: str):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


def check_ledger_and_access():
    section("Ledger / AccessControl / Actuator checks")
    try:
        ledger = Ledger()
        ac = AccessControlPy(initial_admins=["admin"])
        actuator = ActuatorPy(ledger, ac)

        # register
        data = b"selfcheck:temp=23"
        eid = ledger.register(submitter="self_device", data_bytes=data, pointer="self:1")
        if not eid or len(eid) != 64:
            fail("Ledger.register: entry_id inválido")
        else:
            ok(f"Ledger.register: created entry_id {eid[:12]}...")

        entry = ledger.get_entry(eid)
        if entry is None or entry.data_hex != data.hex():
            fail("Ledger.get_entry: contenido no coincide")
        else:
            ok("Ledger.get_entry: entry recuperable y correcto")

        # grant and actuate success
        resource = "door-check"
        grantee = "gatewayA"
        try:
            ac.grant(resource=resource, to=grantee, valid_seconds=30, caller="admin")
            ok("AccessControl.grant: permiso concedido por admin")
        except Exception as e:
            fail(f"AccessControl.grant: fallo al conceder permiso: {e}")
            raise

        if ac.has_access(resource, grantee):
            ok("AccessControl.has_access: grant activo")
        else:
            fail("AccessControl.has_access: grant no encontrado")

        try:
            ev = actuator.actuate(resource=resource, caller=grantee)
            ok(f"Actuator.actuate: actuación permitida (evento {ev.kind})")
        except Exception as e:
            fail(f"Actuator.actuate: fallo inesperado al actuar con permiso: {e}")
            raise

        # revoke and unauthorized actuation fails
        try:
            ac.revoke(resource=resource, to=grantee, caller="admin")
            ok("AccessControl.revoke: permiso revocado por admin")
        except Exception as e:
            fail(f"AccessControl.revoke: fallo al revocar: {e}")
            raise

        if not ac.has_access(resource, grantee):
            ok("AccessControl.has_access: revocación efectiva")
        else:
            fail("AccessControl.has_access: revocación no efectiva")

        try:
            actuator.actuate(resource=resource, caller=grantee)
            fail("Actuator.actuate: NO debería permitir actuar sin permiso (se esperaba excepción)")
        except PermissionError:
            ok("Actuator.actuate: lanza PermissionError cuando el caller no tiene permiso (esperado)")

    except Exception as e:
        print("Traceback (ledger tests):")
        traceback.print_exc()
        fail("Errores durante las comprobaciones del ledger/access/actuator")


def check_uart():
    section("UART simulator checks")
    try:
        st = UARTState()
        # Insecure mode: secure=False should allow DUMP SECRETS
        st.secure = False
        st.locked = False
        out = handle_cmd(st, "DUMP SECRETS")
        if "KEY_VALUE" in out and "ADMIN_PW" in out:
            ok("UART DUMP SECRETS en modo insecure: muestra secretos (esperado en demo)")
        else:
            fail("UART DUMP SECRETS en modo insecure: no mostró secretos (fallo)")

        # Secure mode: test lockout after 3 failed AUTH attempts
        st2 = UARTState()
        st2.secure = True
        st2.locked = True
        for i in range(3):
            res = handle_cmd(st2, "AUTH wrongpass")
        if st2.fail_count >= 3 and st2.locked:
            ok("UART AUTH: after 3 failed attempts, locked / fail_count incrementado (esperado)")
        else:
            fail("UART AUTH: lockout no se activó correctamente")
    except Exception as e:
        traceback.print_exc()
        fail(f"Errores durante comprobaciones UART: {e}")


def check_fw_and_ota():
    section("Firmware / First-boot / OTA signature checks")
    try:
        ds = DeviceState()
        if attack_default_creds(ds):
            ok("FW: attack_default_creds detecta admin/admin inicialmente (esperado)")
        else:
            fail("FW: attack_default_creds NO detectó admin/admin (inesperado)")

        # apply first_boot
        first_boot(ds, "S3cretSelfCheck!")
        if ds.first_boot_done and ds.admin_hash and ds.admin_pass == "":
            ok("FW: first_boot ha hasheado la contraseña y borrado admin_pass (OK)")
        else:
            fail("FW: first_boot no aplicó cambios correctamente")

        # OTA sign & verify
        priv, pub = gen_keys()
        image = b"SELF-CHECK-FIRMWARE"
        sig = sign_image(priv, image)
        if verify_image(pub, image, sig):
            ok("FW OTA: firma y verificación RSA OK")
        else:
            fail("FW OTA: verificación de firma falló")
        # tamper test
        if not verify_image(pub, image + b"X", sig):
            ok("FW OTA: verificación detecta imagen alterada (OK)")
        else:
            fail("FW OTA: verificación NO detectó imagen alterada (FALLA)")

    except Exception as e:
        traceback.print_exc()
        fail(f"Errores durante comprobaciones FW/OTA: {e}")


def check_mqtt_basic():
    section("MQTT simulator checks (publish / spoof / mitm / sniff)")
    try:
        broker = BrokerMem(maxlen=50)
        topic = "selfcheck/topic"
        # publish
        broker.publish(topic, {"t": 10})
        q = broker.subscribe(topic)
        s = sniff(q, maxn=5)
        if any(m["payload"] == {"t": 10} for m in s):
            ok("MQTT publish: mensaje publicado y visible en sniffer")
        else:
            fail("MQTT publish: mensaje NO visible en sniffer")

        # spoof
        fake = {"t": 999, "spoof": True}
        spoofed = spoof(broker, topic, fake)
        s2 = sniff(q, maxn=10)
        if any(m["payload"] == fake for m in s2):
            ok("MQTT spoof: mensaje inyectado y visible (OK)")
        else:
            fail("MQTT spoof: mensaje inyectado NO visible")

        # mitm_publish
        original = {"v": 1}
        mitm_msg = mitm_publish(broker, topic, original)
        s3 = sniff(q, maxn=20)
        # default mitm wraps original into dict with 'original' and 'mitm_note'
        if any(isinstance(m["payload"], dict) and m["payload"].get("original") == original for m in s3):
            ok("MQTT mitm_publish: mensaje modificado e incluido (OK)")
        else:
            fail("MQTT mitm_publish: no se detectó mensaje modificado")

    except Exception as e:
        traceback.print_exc()
        fail(f"Errores durante comprobaciones MQTT: {e}")


def summary():
    print("\n" + "=" * 60)
    print("Self-check completado - revisa los resultados arriba")
    print("Si alguna comprobación falló, revisa los módulos en core/ y vuelve a ejecutar.")
    print("=" * 60 + "\n")


def main():
    print("Starting self-check for iot-secure-app (local-only)...")
    check_ledger_and_access()
    check_uart()
    check_fw_and_ota()
    check_mqtt_basic()
    summary()


if __name__ == "__main__":
    main()
