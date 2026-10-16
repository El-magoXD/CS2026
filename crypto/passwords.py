from __future__ import annotations

from hashlib import pbkdf2_hmac

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

DEFAULT_KDF_ITERATIONS = 200_000


def derive_key_password(password: str, salt: bytes | None = None, iterations: int = DEFAULT_KDF_ITERATIONS) -> tuple[bytes, bytes]:
    """Derive a 16-byte AES key from a password using PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = get_random_bytes(16)
    material = pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=16)
    return material, salt


def encrypt_private_key(private_key: RSA.RsaKey, password: str, salt: bytes | None = None, iterations: int = DEFAULT_KDF_ITERATIONS) -> bytes:
    """Encrypt the RSA private key and return salt + nonce + tag + ciphertext."""
    aes_key, salt = derive_key_password(password, salt=salt, iterations=iterations)
    nonce = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(private_key.export_key(format="DER"))
    return salt + nonce + tag + ciphertext


def decrypt_private_key(payload: bytes, password: str, iterations: int = DEFAULT_KDF_ITERATIONS) -> RSA.RsaKey:
    """Decrypt a protected private key using the password and return the RSA key."""
    if len(payload) < 48:
        raise ValueError("Protected key payload is too short.")

    salt = payload[:16]
    nonce = payload[16:32]
    tag = payload[32:48]
    ciphertext = payload[48:]

    aes_key, _ = derive_key_password(password, salt=salt, iterations=iterations)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    private_key_bytes = cipher.decrypt_and_verify(ciphertext, tag)
    return RSA.import_key(private_key_bytes)
