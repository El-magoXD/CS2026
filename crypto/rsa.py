from __future__ import annotations

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


def generate_rsa_keys() -> tuple[RSA.RsaKey, RSA.RsaKey]:
    """Generate an RSA key pair."""
    private_key = RSA.generate(2048)
    public_key = private_key.public_key()
    return private_key, public_key


def encrypt_with_public(key_material: bytes, public_key: RSA.RsaKey) -> bytes:
    """Encrypt a symmetric key with the RSA public key."""
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(key_material)


def decrypt_with_private(encrypted_key: bytes, private_key: RSA.RsaKey) -> bytes:
    """Decrypt a symmetric key with the RSA private key."""
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted_key)
