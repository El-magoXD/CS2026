#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from Crypto.PublicKey import RSA

from crypto.aes import encrypt_file, generate_aes_key
from crypto.passwords import decrypt_private_key, encrypt_private_key
from crypto.rsa import encrypt_with_public, generate_rsa_keys


DEFAULT_DATA_DIR = Path(__file__).resolve().parent / "data"
DEFAULT_PUBLIC_KEY_PATH = DEFAULT_DATA_DIR / "rsa_public.pem"
DEFAULT_PRIVATE_KEY_PATH = DEFAULT_DATA_DIR / "rsa_private.enc"


def ensure_rsa_keypair(public_key_path: Path, private_key_path: Path, password: str) -> RSA.RsaKey:
    public_key_path.parent.mkdir(parents=True, exist_ok=True)

    public_exists = public_key_path.exists()
    private_exists = private_key_path.exists()
    if public_exists != private_exists:
        raise ValueError(
            "The RSA key pair is incomplete. Restore both key files; "
            "they were not replaced because existing encrypted files may depend on them."
        )

    if public_exists:
        public_key = RSA.import_key(public_key_path.read_bytes())
        private_key = decrypt_private_key(private_key_path.read_bytes(), password)
        if (public_key.n, public_key.e) != (private_key.n, private_key.e):
            raise ValueError("The RSA public and private key files do not belong to the same key pair.")
        return public_key

    private_key, public_key = generate_rsa_keys()
    public_key_path.write_bytes(public_key.export_key(format="PEM"))
    private_key_path.write_bytes(encrypt_private_key(private_key, password))
    return public_key


def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypt a file with a random AES key protected by RSA.")
    parser.add_argument("input_file", type=Path, help="Path to the original file to encrypt.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_DATA_DIR, help="Directory where encrypted files will be stored.")
    parser.add_argument("--password", required=True, help="Password used to encrypt the RSA private key.")
    parser.add_argument("--public-key", type=Path, help="Path to the RSA public key.")
    parser.add_argument("--private-key", type=Path, help="Path to the encrypted RSA private key.")
    args = parser.parse_args()

    input_path = args.input_file.resolve()
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    public_key_path = args.public_key.resolve() if args.public_key is not None else output_dir / "rsa_public.pem"
    private_key_path = args.private_key.resolve() if args.private_key is not None else output_dir / "rsa_private.enc"
    try:
        public_key = ensure_rsa_keypair(public_key_path, private_key_path, args.password)
    except ValueError as exc:
        parser.error(
            f"cannot use the RSA key pair in {output_dir}: {exc}. "
            "Use the password that protected the existing private key."
        )

    aes_key = generate_aes_key()
    encrypted_file_path = output_dir / f"{input_path.stem}.enc"
    encrypted_key_path = output_dir / f"{input_path.stem}.key.enc"

    encrypt_file(input_path, encrypted_file_path, aes_key)
    encrypted_key_path.write_bytes(encrypt_with_public(aes_key, public_key))

    print(f"Archivo cifrado: {encrypted_file_path}")
    print(f"Clave AES cifrada con RSA: {encrypted_key_path}")
    print(f"Clave privada guardada protegida con contraseña: {private_key_path}")


if __name__ == "__main__":
    main()
