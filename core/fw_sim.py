# core/fw_sim.py
# Simulador de estado de dispositivo y utilidades de firma de firmware usando cryptography.
# Todo local-offline: genera claves en memoria, firma/verify con RSA-PSS + SHA256.

from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Tuple
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


@dataclass
class DeviceState:
    """
    Estado simplificado del dispositivo para prácticas de firmware/OTA.
    - firmware: bytes (contenido del firmware o imagen)
    - admin_user: nombre de usuario administrador
    - admin_pass: contraseña en texto claro (temporal; se borra en first_boot)
    - admin_hash: sha256 hex de la contraseña (establecido en first_boot)
    - ota_version: versión conocida de OTA (string)
    - first_boot_done: booleano indicando si se hizo el primer arranque/seteo
    """
    firmware: bytes = b""
    admin_user: str = "admin"
    admin_pass: str = "admin"  # por defecto inseguro; se debe cambiar en first_boot
    admin_hash: str = ""
    ota_version: str = "0.0.0"
    first_boot_done: bool = False


# ------------------ Utilidades ------------------ #

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ------------------ Funciones requeridas ------------------ #

def attack_default_creds(state: DeviceState) -> bool:
    """
    Devuelve True si las credenciales indican que el dispositivo usa admin/admin.
    Esto comprueba tanto el campo en texto (si existe) como el hash (si solo quedó el hash).
    """
    # Comprueba texto claro primero
    if state.admin_user == "admin" and state.admin_pass == "admin":
        return True
    # Si solo queda hash, comparar con hash de "admin"
    if state.admin_user == "admin" and state.admin_hash:
        return state.admin_hash == _sha256_hex(b"admin")
    return False


def first_boot(state: DeviceState, new_pass: str) -> None:
    """
    Operación de primer arranque:
    - Calcula hash SHA-256 de new_pass y lo guarda en admin_hash.
    - Borra admin_pass en texto.
    - Marca first_boot_done True.
    """
    if not isinstance(new_pass, str) or new_pass == "":
        raise ValueError("new_pass debe ser una cadena no vacía")
    state.admin_hash = _sha256_hex(new_pass.encode("utf-8"))
    state.admin_pass = ""  # eliminar texto claro
    state.first_boot_done = True


def verify_login(state: DeviceState, user: str, password: str) -> bool:
    """
    Verifica credenciales:
    - Si state.admin_pass contiene texto (no vacío), lo compara directamente.
    - Si no, usa admin_hash (SHA-256 hex) para comparar.
    """
    if user != state.admin_user:
        return False

    if state.admin_pass:
        # todavía hay password en claro
        return password == state.admin_pass

    if state.admin_hash:
        return _sha256_hex(password.encode("utf-8")) == state.admin_hash

    # Sin password establecido
    return False


# ------------------ Firma / Verificación RSA ------------------ #

def gen_keys(key_size: int = 2048) -> Tuple[bytes, bytes]:
    """
    Genera un par RSA en memoria.
    Retorna (private_pem_bytes, public_pem_bytes) sin cifrar.
    """
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = priv.public_key()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_pem, pub_pem


def sign_image(priv_pem: bytes, image_bytes: bytes) -> bytes:
    """
    Firma image_bytes usando la clave privada en PEM (RSA-PSS + SHA256).
    Retorna la firma (bytes).
    """
    if not isinstance(priv_pem, (bytes, bytearray)):
        raise TypeError("priv_pem debe ser bytes PEM")
    if not isinstance(image_bytes, (bytes, bytearray)):
        raise TypeError("image_bytes debe ser bytes")

    priv_key = serialization.load_pem_private_key(priv_pem, password=None)
    signature = priv_key.sign(
        image_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature


def verify_image(pub_pem: bytes, image_bytes: bytes, sig: bytes) -> bool:
    """
    Verifica la firma sig sobre image_bytes usando la clave pública en PEM.
    Retorna True si la verificación es correcta, False si no.
    """
    if not isinstance(pub_pem, (bytes, bytearray)):
        raise TypeError("pub_pem debe ser bytes PEM")
    if not isinstance(image_bytes, (bytes, bytearray)) or not isinstance(sig, (bytes, bytearray)):
        raise TypeError("image_bytes y sig deben ser bytes")

    pub_key = serialization.load_pem_public_key(pub_pem)
    try:
        pub_key.verify(
            sig,
            image_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


# ------------------ Demo en línea de comandos ------------------ #
if __name__ == "__main__":
    print("FW_SIM DEMO\n------------")

    # Estado inicial (por defecto inseguro: admin/admin)
    st = DeviceState()
    print("Estado inicial:", asdict(st))
    print("¿Vulnerable a credenciales por defecto?", attack_default_creds(st))

    # Simular primer arranque: establecer contraseña segura
    print("\nEjecutando first_boot con contraseña 'S3cur3-Pass!'")
    first_boot(st, "S3cur3-Pass!")
    print("Estado después de first_boot:", {"admin_user": st.admin_user, "admin_pass": st.admin_pass, "admin_hash": st.admin_hash[:16] + "...", "first_boot_done": st.first_boot_done})
    print("¿Vulnerable a credenciales por defecto?", attack_default_creds(st))

    # Verificar login correcto e incorrecto
    print("\nVerificando logins:")
    print("login admin / wrong ->", verify_login(st, "admin", "wrong"))
    print("login admin / S3cur3-Pass! ->", verify_login(st, "admin", "S3cur3-Pass!"))

    # Generar claves y firmar una imagen
    print("\nGenerando par de claves RSA en memoria...")
    priv_pem, pub_pem = gen_keys()
    print("Priv key PEM (trunc):", priv_pem.decode("utf-8").splitlines()[0])
    print("Pub key PEM (trunc):", pub_pem.decode("utf-8").splitlines()[0])

    sample_image = b"FAKE-FIRMWARE-V1-BYTES"
    print("\nFirmando imagen de prueba:", sample_image)
    signature = sign_image(priv_pem, sample_image)
    print("Firma (bytes len):", len(signature))

    print("Verificación correcta (debe ser True):", verify_image(pub_pem, sample_image, signature))
    print("Verificación con otro contenido (debe ser False):", verify_image(pub_pem, b"tampered", signature))

    # Resultado final
    print("\nDemo completado.")
