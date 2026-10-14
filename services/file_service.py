from __future__ import annotations

from pathlib import Path

from Crypto.PublicKey import RSA

from crypto.aes import decrypt_bytes, encrypt_bytes, generate_aes_key
from crypto.passwords import decrypt_private_key, encrypt_private_key
from crypto.rsa import decrypt_with_private, encrypt_with_public, generate_rsa_keys
from database.database import (
    DEFAULT_DATABASE_PATH,
    KeyPairRecord,
    StoredFileSummary,
    get_encrypted_file,
    get_keypair,
    initialize_database,
    list_encrypted_files,
    save_encrypted_file,
    save_keypair,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LEGACY_PUBLIC_KEY_PATH = PROJECT_ROOT / "data" / "rsa_public.pem"
LEGACY_PRIVATE_KEY_PATH = PROJECT_ROOT / "data" / "rsa_private.enc"


def _validate_keypair(public_key_bytes: bytes, encrypted_private_key: bytes, password: str) -> RSA.RsaKey:
    public_key = RSA.import_key(public_key_bytes)
    private_key = decrypt_private_key(encrypted_private_key, password)
    if (public_key.n, public_key.e) != (private_key.n, private_key.e):
        raise ValueError("The RSA public and private keys do not belong to the same pair.")
    return public_key


def _load_or_create_keypair(
    password: str,
    database_path: str | Path,
    legacy_public_key_path: str | Path,
    legacy_private_key_path: str | Path,
) -> RSA.RsaKey:
    existing = get_keypair(database_path)
    if existing is not None:
        return _validate_keypair(
            existing.public_key,
            existing.encrypted_private_key,
            password,
        )

    public_path = Path(legacy_public_key_path)
    private_path = Path(legacy_private_key_path)
    if public_path.exists() != private_path.exists():
        raise ValueError(
            "The existing RSA key pair is incomplete. Restore both files before continuing."
        )

    if public_path.exists():
        public_key_bytes = public_path.read_bytes()
        encrypted_private_key = private_path.read_bytes()
        public_key = _validate_keypair(public_key_bytes, encrypted_private_key, password)
    else:
        private_key, public_key = generate_rsa_keys()
        public_key_bytes = public_key.export_key(format="PEM")
        encrypted_private_key = encrypt_private_key(private_key, password)

    save_keypair(public_key_bytes, encrypted_private_key, database_path)

    # Another process may have initialized the singleton key pair concurrently.
    stored = get_keypair(database_path)
    if stored is None:
        raise RuntimeError("The RSA key pair could not be saved to the database.")
    return _validate_keypair(stored.public_key, stored.encrypted_private_key, password)


def encrypt_file_to_database(
    input_path: str | Path,
    password: str,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
    legacy_public_key_path: str | Path = LEGACY_PUBLIC_KEY_PATH,
    legacy_private_key_path: str | Path = LEGACY_PRIVATE_KEY_PATH,
) -> int:
    """Encrypt a local file and save its ciphertext and wrapped key in SQLite."""
    source = Path(input_path).expanduser()
    if not source.is_file():
        raise FileNotFoundError(f"Input file not found: {source}")
    if not password:
        raise ValueError("A password is required to protect the RSA private key.")

    initialize_database(database_path)
    public_key = _load_or_create_keypair(
        password,
        database_path,
        legacy_public_key_path,
        legacy_private_key_path,
    )

    plaintext = source.read_bytes()
    aes_key = generate_aes_key()
    nonce, tag, ciphertext = encrypt_bytes(plaintext, aes_key)
    encrypted_content = nonce + tag + ciphertext
    encrypted_aes_key = encrypt_with_public(aes_key, public_key)

    return save_encrypted_file(
        source.name,
        encrypted_content,
        encrypted_aes_key,
        len(plaintext),
        database_path,
    )


def decrypt_file_from_database(
    file_id: int,
    password: str,
    output_path: str | Path,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> Path:
    """Decrypt a database entry and write the verified plaintext to disk."""
    stored_file = get_encrypted_file(file_id, database_path)
    if stored_file is None:
        raise FileNotFoundError(f"No encrypted file with database ID {file_id}.")

    keypair: KeyPairRecord | None = get_keypair(database_path)
    if keypair is None:
        raise ValueError("The database does not contain the RSA key pair for this file.")
    private_key = decrypt_private_key(keypair.encrypted_private_key, password)
    public_key = RSA.import_key(keypair.public_key)
    if (public_key.n, public_key.e) != (private_key.n, private_key.e):
        raise ValueError("The RSA public and private keys do not belong to the same pair.")

    aes_key = decrypt_with_private(stored_file.encrypted_aes_key, private_key)
    if len(stored_file.encrypted_content) < 32:
        raise ValueError("The encrypted file record is too short to contain a nonce and tag.")

    nonce = stored_file.encrypted_content[:16]
    tag = stored_file.encrypted_content[16:32]
    ciphertext = stored_file.encrypted_content[32:]
    plaintext = decrypt_bytes(ciphertext, aes_key, nonce, tag)

    destination = Path(output_path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(plaintext)
    return destination


def get_database_files(
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> list[StoredFileSummary]:
    return list_encrypted_files(database_path)
