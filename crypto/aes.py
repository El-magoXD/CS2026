from __future__ import annotations

from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def generate_aes_key(length: int = 16) -> bytes:
    """Generate a symmetric key for AES-128 by default."""
    return get_random_bytes(length)


def encrypt_bytes(plaintext: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    """Encrypt bytes using AES-GCM and return nonce, tag, and ciphertext."""
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, tag, ciphertext


def decrypt_bytes(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
    """Decrypt AES-GCM payload and verify integrity."""
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def encrypt_file(input_path: str | Path, output_path: str | Path, key: bytes) -> tuple[bytes, bytes, bytes]:
    """Encrypt a file in place using AES-GCM and return nonce, tag, and ciphertext."""
    input_path = Path(input_path)
    output_path = Path(output_path)

    plaintext = input_path.read_bytes()
    nonce, tag, ciphertext = encrypt_bytes(plaintext, key)
    output_path.write_bytes(nonce + tag + ciphertext)
    return nonce, tag, ciphertext


def decrypt_file(input_path: str | Path, output_path: str | Path, key: bytes) -> bytes:
    """Decrypt a file previously encrypted with AES-GCM."""
    input_path = Path(input_path)
    output_path = Path(output_path)

    blob = input_path.read_bytes()
    if len(blob) < 32:
        raise ValueError("Encrypted file is too short to contain a valid nonce and tag.")

    nonce = blob[:16]
    tag = blob[16:32]
    ciphertext = blob[32:]
    plaintext = decrypt_bytes(ciphertext, key, nonce, tag)
    output_path.write_bytes(plaintext)
    return plaintext
