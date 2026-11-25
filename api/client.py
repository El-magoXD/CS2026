from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from Crypto.PublicKey import RSA

from crypto.aes import decrypt_bytes, encrypt_bytes, generate_aes_key
from crypto.passwords import decrypt_private_key, encrypt_private_key
from crypto.rsa import decrypt_with_private, encrypt_with_public, generate_rsa_keys


DEFAULT_API_URL = "http://127.0.0.1:8000"
API_BASE_URL = os.environ.get("CS2026_API_URL", DEFAULT_API_URL).rstrip("/")
_TIMEOUT = httpx.Timeout(connect=10, read=300, write=300, pool=10)


@dataclass(frozen=True)
class RemoteSession:
    id: int
    username: str
    private_key: RSA.RsaKey
    access_token: str


@dataclass(frozen=True)
class RemoteFileSummary:
    id: int
    original_name: str
    created_at: str
    size_bytes: int


@dataclass(frozen=True)
class SharedFileSummary:
    id: int
    file_id: int
    original_name: str
    shared_by: str
    created_at: str
    size_bytes: int


def _client(session: RemoteSession | None = None) -> httpx.Client:
    parsed_url = urlsplit(API_BASE_URL)
    if parsed_url.scheme == "https":
        pass
    elif parsed_url.scheme == "http" and parsed_url.hostname in {
        "127.0.0.1",
        "localhost",
        "::1",
    }:
        pass
    else:
        raise ValueError(
            "La API remota debe usar HTTPS. HTTP solo se permite para localhost."
        )
    headers = (
        {"Authorization": f"Bearer {session.access_token}"}
        if session is not None
        else {}
    )
    return httpx.Client(
        base_url=API_BASE_URL,
        headers=headers,
        timeout=_TIMEOUT,
    )


def _request(
    method: str,
    endpoint: str,
    session: RemoteSession | None = None,
    **kwargs: object,
) -> httpx.Response:
    try:
        with _client(session) as client:
            response = client.request(method, endpoint, **kwargs)
    except httpx.RequestError as exc:
        raise ConnectionError(
            f"No se pudo conectar con la API en {API_BASE_URL}: {exc}"
        ) from exc
    if response.is_error:
        try:
            detail = response.json().get("detail", response.text)
        except ValueError:
            detail = response.text
        raise RuntimeError(f"Error de API ({response.status_code}): {detail}")
    return response


def register_remote_user(username: str, password: str) -> None:
    normalized_username = username.strip()
    if not normalized_username or len(normalized_username) > 64:
        raise ValueError("El usuario debe tener entre 1 y 64 caracteres.")
    if len(password) < 8:
        raise ValueError("La contraseña debe tener al menos 8 caracteres.")
    private_key, public_key = generate_rsa_keys()
    encrypted_private_key = encrypt_private_key(private_key, password)
    _request(
        "POST",
        "/api/auth/register",
        json={
            "username": normalized_username,
            "password": password,
            "public_key": public_key.export_key(format="PEM").decode("ascii"),
            "encrypted_private_key": base64.b64encode(encrypted_private_key).decode("ascii"),
        },
    )


def authenticate_remote_user(username: str, password: str) -> RemoteSession:
    response = _request(
        "POST",
        "/api/auth/login",
        json={"username": username.strip(), "password": password},
    ).json()
    try:
        private_key = decrypt_private_key(
            base64.b64decode(response["encrypted_private_key"], validate=True),
            password,
        )
        public_key = RSA.import_key(response["public_key"])
    except (KeyError, ValueError, TypeError) as exc:
        raise ValueError(
            "El servidor devolvió datos de clave inválidos o no se pudo desbloquear "
            "la clave privada."
        ) from exc
    if (public_key.n, public_key.e) != (private_key.n, private_key.e):
        raise ValueError("La clave pública y la clave privada de la cuenta no coinciden.")
    return RemoteSession(
        id=int(response["user_id"]),
        username=str(response["username"]),
        private_key=private_key,
        access_token=str(response["access_token"]),
    )


def logout_remote_user(session: RemoteSession) -> None:
    _request("POST", "/api/auth/logout", session)


def search_remote_users(
    query: str,
    session: RemoteSession,
) -> list[dict[str, str | int]]:
    response = _request(
        "GET",
        "/api/users/search",
        session,
        params={"query": query},
    )
    return response.json()


def _parse_file(row: dict[str, object]) -> RemoteFileSummary:
    return RemoteFileSummary(
        id=int(row["id"]),
        original_name=str(row["original_name"]),
        created_at=str(row["created_at"]),
        size_bytes=int(row["size_bytes"]),
    )


def list_remote_files(session: RemoteSession) -> list[RemoteFileSummary]:
    rows = _request("GET", "/api/files", session).json()
    return [_parse_file(row) for row in rows]


def list_received_shares(session: RemoteSession) -> list[SharedFileSummary]:
    rows = _request("GET", "/api/shares/received", session).json()
    return [
        SharedFileSummary(
            id=int(row["id"]),
            file_id=int(row["file_id"]),
            original_name=str(row["original_name"]),
            shared_by=str(row["shared_by"]),
            created_at=str(row["created_at"]),
            size_bytes=int(row["size_bytes"]),
        )
        for row in rows
    ]


def encrypt_file_to_remote(
    input_path: str | Path,
    session: RemoteSession,
) -> int:
    source = Path(input_path).expanduser()
    if not source.is_file():
        raise FileNotFoundError(f"No existe el archivo seleccionado: {source}")
    plaintext = source.read_bytes()
    aes_key = generate_aes_key()
    nonce, tag, ciphertext = encrypt_bytes(plaintext, aes_key)
    encrypted_content = nonce + tag + ciphertext
    encrypted_aes_key = encrypt_with_public(aes_key, session.private_key.public_key())
    response = _request(
        "POST",
        "/api/files",
        session,
        params={
            "original_name": source.name,
            "size_bytes": len(plaintext),
        },
        content=encrypted_content,
        headers={
            "Content-Type": "application/octet-stream",
            "X-Encrypted-AES-Key": base64.b64encode(encrypted_aes_key).decode("ascii"),
        },
    )
    return int(response.json()["id"])


def _decrypt_remote_content(
    content: bytes,
    encrypted_aes_key: bytes,
    private_key: RSA.RsaKey,
    output_path: str | Path,
) -> Path:
    if len(content) < 32:
        raise ValueError("El archivo cifrado está incompleto.")
    aes_key = decrypt_with_private(encrypted_aes_key, private_key)
    plaintext = decrypt_bytes(content[32:], aes_key, content[:16], content[16:32])
    destination = Path(output_path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(plaintext)
    return destination


def decrypt_remote_file(
    file_id: int,
    output_path: str | Path,
    session: RemoteSession,
) -> Path:
    details = _request("GET", f"/api/files/{file_id}", session).json()
    encrypted_aes_key = base64.b64decode(details["encrypted_aes_key"], validate=True)
    content = _request("GET", f"/api/files/{file_id}/content", session).content
    return _decrypt_remote_content(content, encrypted_aes_key, session.private_key, output_path)


def share_remote_file(
    file_id: int,
    recipient_username: str,
    session: RemoteSession,
) -> None:
    details = _request("GET", f"/api/files/{file_id}", session).json()
    encrypted_aes_key = base64.b64decode(details["encrypted_aes_key"], validate=True)
    aes_key = decrypt_with_private(encrypted_aes_key, session.private_key)
    recipients = search_remote_users(recipient_username, session)
    recipient = next(
        (
            candidate
            for candidate in recipients
            if str(candidate["username"]).casefold() == recipient_username.strip().casefold()
        ),
        None,
    )
    if recipient is None:
        raise ValueError("No existe otro usuario con ese nombre.")
    recipient_public_key = RSA.import_key(str(recipient["public_key"]))
    wrapped_key = encrypt_with_public(aes_key, recipient_public_key)
    _request(
        "POST",
        f"/api/files/{file_id}/shares",
        session,
        json={
            "recipient_username": str(recipient["username"]),
            "encrypted_aes_key": base64.b64encode(wrapped_key).decode("ascii"),
        },
    )


def decrypt_received_file(
    share_id: int,
    output_path: str | Path,
    session: RemoteSession,
) -> Path:
    key_response = _request("GET", f"/api/shares/{share_id}/key", session).json()
    encrypted_aes_key = base64.b64decode(key_response["encrypted_aes_key"], validate=True)
    content = _request("GET", f"/api/shares/{share_id}/content", session).content
    return _decrypt_remote_content(content, encrypted_aes_key, session.private_key, output_path)


def revoke_remote_share(
    file_id: int,
    recipient_username: str,
    session: RemoteSession,
) -> None:
    _request(
        "DELETE",
        f"/api/files/{file_id}/shares",
        session,
        params={"recipient_username": recipient_username},
    )
