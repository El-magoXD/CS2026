"""Compatibility wrapper around the cryptographic helpers."""

from crypto.passwords import (
    decrypt_private_key,
    derive_key_password,
    encrypt_private_key,
)
from crypto.rsa import decrypt_with_private, encrypt_with_public, generate_rsa_keys


def generar_claves():
    """Genera el par de claves RSA (2048 bits)."""
    return generate_rsa_keys()


def cifrar_con_publica(clave_aes, clave_publica):
    """Cifra la clave AES con la clave pública RSA."""
    return encrypt_with_public(clave_aes, clave_publica)


def descifrar_con_privada(clave_cifrada, clave_privada):
    """Descifra la clave AES con la clave privada RSA."""
    return decrypt_with_private(clave_cifrada, clave_privada)


def derivar_clave_password(password: str) -> bytes:
    """Deriva una clave AES-128 a partir de la contraseña usando PBKDF2."""
    return derive_key_password(password)[0]


def proteger_clave_privada(clave_privada, password: str) -> bytes:
    """Cifra la clave privada RSA con AES-128 usando una contraseña."""
    return encrypt_private_key(clave_privada, password)


def recuperar_clave_privada(payload: bytes, password: str):
    """Descifra la clave privada RSA usando la contraseña."""
    return decrypt_private_key(payload, password)
