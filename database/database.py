from __future__ import annotations

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE_PATH = PROJECT_ROOT / "data" / "secure_storage.sqlite3"


@dataclass(frozen=True)
class KeyPairRecord:
    public_key: bytes
    encrypted_private_key: bytes


@dataclass(frozen=True)
class StoredFile:
    id: int
    original_name: str
    created_at: str
    size_bytes: int
    encrypted_content: bytes
    encrypted_aes_key: bytes


@dataclass(frozen=True)
class StoredFileSummary:
    id: int
    original_name: str
    created_at: str
    size_bytes: int


@contextmanager
def _connect(database_path: str | Path) -> Generator[sqlite3.Connection, None, None]:
    path = Path(database_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path), timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database(database_path: str | Path = DEFAULT_DATABASE_PATH) -> None:
    """Create the local encrypted-file and key-pair tables if they do not exist."""
    with _connect(database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS keypairs (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                public_key BLOB NOT NULL,
                encrypted_private_key BLOB NOT NULL,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );

            CREATE TABLE IF NOT EXISTS encrypted_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_name TEXT NOT NULL,
                encrypted_content BLOB NOT NULL,
                encrypted_aes_key BLOB NOT NULL,
                keypair_id INTEGER NOT NULL DEFAULT 1 REFERENCES keypairs(id),
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0)
            );

            CREATE INDEX IF NOT EXISTS idx_encrypted_files_created_at
                ON encrypted_files(created_at);
            """
        )


def get_keypair(database_path: str | Path = DEFAULT_DATABASE_PATH) -> KeyPairRecord | None:
    initialize_database(database_path)
    with _connect(database_path) as connection:
        row = connection.execute(
            "SELECT public_key, encrypted_private_key FROM keypairs WHERE id = 1"
        ).fetchone()
    if row is None:
        return None
    return KeyPairRecord(bytes(row["public_key"]), bytes(row["encrypted_private_key"]))


def save_keypair(
    public_key: bytes,
    encrypted_private_key: bytes,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> bool:
    """Save the local key pair once; return False if another pair is already stored."""
    initialize_database(database_path)
    with _connect(database_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO keypairs (id, public_key, encrypted_private_key)
            VALUES (1, ?, ?)
            ON CONFLICT(id) DO NOTHING
            """,
            (sqlite3.Binary(public_key), sqlite3.Binary(encrypted_private_key)),
        )
    return cursor.rowcount == 1


def save_encrypted_file(
    original_name: str,
    encrypted_content: bytes,
    encrypted_aes_key: bytes,
    original_size: int,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> int:
    """Persist ciphertext and its RSA-wrapped AES key and return the database ID."""
    initialize_database(database_path)
    with _connect(database_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO encrypted_files (
                original_name,
                encrypted_content,
                encrypted_aes_key,
                size_bytes
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                original_name,
                sqlite3.Binary(encrypted_content),
                sqlite3.Binary(encrypted_aes_key),
                original_size,
            ),
        )
        return int(cursor.lastrowid)


def list_encrypted_files(
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> list[StoredFileSummary]:
    initialize_database(database_path)
    with _connect(database_path) as connection:
        rows = connection.execute(
            """
            SELECT id, original_name, created_at, size_bytes
            FROM encrypted_files
            ORDER BY created_at DESC, id DESC
            """
        ).fetchall()
    return [
        StoredFileSummary(
            id=int(row["id"]),
            original_name=str(row["original_name"]),
            created_at=str(row["created_at"]),
            size_bytes=int(row["size_bytes"]),
        )
        for row in rows
    ]


def get_encrypted_file(
    file_id: int,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> StoredFile | None:
    initialize_database(database_path)
    with _connect(database_path) as connection:
        row = connection.execute(
            """
            SELECT id, original_name, created_at, size_bytes,
                   encrypted_content, encrypted_aes_key
            FROM encrypted_files
            WHERE id = ?
            """,
            (file_id,),
        ).fetchone()
    if row is None:
        return None
    return StoredFile(
        id=int(row["id"]),
        original_name=str(row["original_name"]),
        created_at=str(row["created_at"]),
        size_bytes=int(row["size_bytes"]),
        encrypted_content=bytes(row["encrypted_content"]),
        encrypted_aes_key=bytes(row["encrypted_aes_key"]),
    )
