from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from Crypto.PublicKey import RSA

from crypto.aes import decrypt_bytes, encrypt_bytes, generate_aes_key
from crypto.passwords import decrypt_private_key, encrypt_private_key
from crypto.rsa import decrypt_with_private, encrypt_with_public, generate_rsa_keys
from database.database import (
    DEFAULT_DATABASE_PATH,
    StoredFileSummary,
    UserRecord,
    create_user,
    get_encrypted_file,
    get_user,
    get_user_by_id,
    list_encrypted_files,
    save_encrypted_file,
)


@dataclass(frozen=True)
class AuthenticatedUser:
    id: int
    username: str
    private_key: RSA.RsaKey


def _validate_user_keypair(user: UserRecord, password: str) -> RSA.RsaKey:
    public_key = RSA.import_key(user.public_key)
    private_key = decrypt_private_key(user.encrypted_private_key, password)
    if (public_key.n, public_key.e) != (private_key.n, private_key.e):
        raise ValueError("The user's public and private keys do not match.")
    return private_key


def register_user(
    username: str,
    password: str,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> int:
    normalized_username = username.strip()
    if not normalized_username:
        raise ValueError("The username cannot be empty.")
    if len(normalized_username) > 64:
        raise ValueError("The username cannot exceed 64 characters.")
    if not password:
        raise ValueError("The password cannot be empty.")

    private_key, public_key = generate_rsa_keys()
    encrypted_private_key = encrypt_private_key(private_key, password)
    return create_user(
        normalized_username,
        public_key.export_key(format="PEM"),
        encrypted_private_key,
        database_path,
    )


def authenticate_user(
    username: str,
    password: str,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> AuthenticatedUser:
    user = get_user(username, database_path)
    if user is None:
        raise ValueError("No existe una cuenta con ese nombre de usuario.")
    if not password:
        raise ValueError("Introduce la contraseña de la clave privada.")

    try:
        private_key = _validate_user_keypair(user, password)
    except ValueError as exc:
        raise ValueError(
            "No se pudo desbloquear la clave privada. Comprueba la contraseña "
            "o verifica que los datos no estén dañados."
        ) from exc
    return AuthenticatedUser(user.id, user.username, private_key)


def encrypt_file_to_database(
    input_path: str | Path,
    owner_id: int,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> int:
    """Encrypt a file for a logged-in user and save its ciphertext in SQLite."""
    source = Path(input_path).expanduser()
    if not source.is_file():
        raise FileNotFoundError(f"Input file not found: {source}")

    user = get_user_by_id(owner_id, database_path)
    if user is None:
        raise ValueError("The active user does not exist in the database.")

    public_key = RSA.import_key(user.public_key)
    plaintext = source.read_bytes()
    aes_key = generate_aes_key()
    nonce, tag, ciphertext = encrypt_bytes(plaintext, aes_key)
    encrypted_content = nonce + tag + ciphertext
    encrypted_aes_key = encrypt_with_public(aes_key, public_key)

    return save_encrypted_file(
        owner_id,
        source.name,
        encrypted_content,
        encrypted_aes_key,
        len(plaintext),
        database_path,
    )


def decrypt_file_from_database(
    file_id: int,
    owner_id: int,
    private_key: RSA.RsaKey,
    output_path: str | Path,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> Path:
    """Decrypt one file belonging to the authenticated user."""
    stored_file = get_encrypted_file(file_id, owner_id, database_path)
    if stored_file is None:
        raise FileNotFoundError(
            f"No encrypted file with ID {file_id} belongs to the active user."
        )

    user = get_user_by_id(owner_id, database_path)
    if user is None:
        raise ValueError("The active user does not exist in the database.")
    public_key = RSA.import_key(user.public_key)
    if (public_key.n, public_key.e) != (private_key.n, private_key.e):
        raise ValueError("The active private key does not match this user's public key.")

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


def decrypt_external_file(
    encrypted_file: str | Path,
    encrypted_key_file: str | Path,
    private_key: RSA.RsaKey,
    output_path: str | Path,
) -> Path:
    encrypted_path = Path(encrypted_file).expanduser()
    key_path = Path(encrypted_key_file).expanduser()
    blob = encrypted_path.read_bytes()
    if len(blob) < 32:
        raise ValueError("The encrypted file is too short to contain a nonce and tag.")

    aes_key = decrypt_with_private(key_path.read_bytes(), private_key)
    nonce = blob[:16]
    tag = blob[16:32]
    plaintext = decrypt_bytes(blob[32:], aes_key, nonce, tag)

    destination = Path(output_path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(plaintext)
    return destination


def get_database_files(
    owner_id: int,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> list[StoredFileSummary]:
    return list_encrypted_files(owner_id, database_path)
