"""Encrypt and decrypt media/pablo.jpg using AES-128-CBC."""

from pathlib import Path
from secrets import token_bytes
import subprocess


SOURCE = Path("media/pablo.jpg")
ENCRYPTED = SOURCE.with_name(f"{SOURCE.stem}_encrypted.aes")
DECRYPTED = SOURCE.with_name(f"{SOURCE.stem}_decrypt{SOURCE.suffix}")


def main() -> None:
    # AES-128 needs a 16-byte key and CBC needs a unique 16-byte IV.
    # Save the key securely if this file must be decrypted in a later run.
    key = token_bytes(16)
    iv = token_bytes(16)

    encrypted = subprocess.run(
        ["openssl", "enc", "-aes-128-cbc", "-K", key.hex(), "-iv", iv.hex()],
        input=SOURCE.read_bytes(),
        capture_output=True,
        check=True,
    ).stdout
    # Prefix the IV so decryption can recover it from the encrypted file.
    ENCRYPTED.write_bytes(iv + encrypted)

    # Read the encrypted file back, then decrypt it (rather than reusing the
    # in-memory encrypted bytes) to verify the file can be recovered.
    encrypted_data = ENCRYPTED.read_bytes()
    stored_iv, ciphertext = encrypted_data[:16], encrypted_data[16:]
    decrypted = subprocess.run(
        ["openssl", "enc", "-d", "-aes-128-cbc", "-K", key.hex(), "-iv", stored_iv.hex()],
        input=ciphertext,
        capture_output=True,
        check=True,
    ).stdout
    DECRYPTED.write_bytes(decrypted)

    print(f"Encrypted: {ENCRYPTED}")
    print(f"Decrypted: {DECRYPTED}")


if __name__ == "__main__":
    main()
