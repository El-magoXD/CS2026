#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

from crypto.aes import decrypt_file
from crypto.passwords import decrypt_private_key
from crypto.rsa import decrypt_with_private


DEFAULT_PRIVATE_KEY_PATH = Path(__file__).resolve().parent / "data" / "rsa_private.enc"


def main() -> None:
    parser = argparse.ArgumentParser(description="Decrypt a file encrypted with AES and protected by RSA.")
    parser.add_argument("--encrypted-file", type=Path, required=True, help="Path to the encrypted file (.enc).")
    parser.add_argument("--key-file", type=Path, required=True, help="Path to the encrypted AES key (.key.enc).")
    parser.add_argument("--output", type=Path, required=True, help="Output path for the decrypted file.")
    parser.add_argument("--password", required=True, help="Password used to decrypt the stored RSA private key.")
    parser.add_argument("--private-key", type=Path, help="Path to the encrypted RSA private key.")
    args = parser.parse_args()

    if not args.encrypted_file.exists():
        raise FileNotFoundError(f"Encrypted file not found: {args.encrypted_file}")
    if not args.key_file.exists():
        raise FileNotFoundError(f"Encrypted key file not found: {args.key_file}")

    private_key_path = args.private_key.resolve() if args.private_key is not None else args.encrypted_file.parent / "rsa_private.enc"
    if not private_key_path.exists():
        private_key_path = DEFAULT_PRIVATE_KEY_PATH
    if not private_key_path.exists():
        raise FileNotFoundError(f"Private key not found: {private_key_path}")

    try:
        private_key = decrypt_private_key(private_key_path.read_bytes(), args.password)
    except ValueError:
        parser.error(
            f"cannot unlock {private_key_path}; the password may be incorrect, "
            "or the protected private-key file may be damaged or use another format"
        )

    try:
        aes_key = decrypt_with_private(args.key_file.read_bytes(), private_key)
    except ValueError:
        parser.error(
            f"{args.key_file} was not encrypted for the RSA private key in {private_key_path}"
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    decrypt_file(args.encrypted_file, args.output, aes_key)
    print(f"Archivo desencriptado correctamente: {args.output}")


if __name__ == "__main__":
    main()
