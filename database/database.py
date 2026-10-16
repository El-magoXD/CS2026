from __future__ import annotations

import os
import sqlite3
import sys
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if getattr(sys, "frozen", False):
    DATA_DIR = Path(os.environ["LOCALAPPDATA"]) / "CS2026"
else:
    DATA_DIR = PROJECT_ROOT / "data"

DEFAULT_DATABASE_PATH = DATA_DIR / "secure_storage.sqlite3"


@dataclass(frozen=True)
class UserRecord:
    id: int
    username: str
    public_key: bytes
    encrypted_private_key: bytes


@dataclass(frozen=True)
class StoredFile:
    id: int
    owner_id: int
    original_name: str
    created_at: str
    size_bytes: int
    encrypted_content: bytes
    encrypted_aes_key: bytes


@dataclass(frozen=True)
class StoredFileSummary:
    id: int
    owner_id: int
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


def _table_names(connection: sqlite3.Connection) -> set[str]:
    rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
    ).fetchall()
    return {str(row["name"]) for row in rows}


def _migrate_legacy_keypair(connection: sqlite3.Connection, table_names: set[str]) -> int | None:
    if "keypairs" not in table_names:
        return None

    row = connection.execute(
        "SELECT public_key, encrypted_private_key FROM keypairs WHERE id = 1"
    ).fetchone()
    if row is None:
        return None

    public_key = bytes(row["public_key"])
    private_key = bytes(row["encrypted_private_key"])
    match = connection.execute(
        "SELECT id FROM users WHERE public_key = ?",
        (sqlite3.Binary(public_key),),
    ).fetchone()
    if match is not None:
        return int(match["id"])

    username = "usuario"
    suffix = 1
    while connection.execute(
        "SELECT 1 FROM users WHERE username = ? COLLATE NOCASE",
        (username,),
    ).fetchone():
        username = f"usuario_legacy_{suffix}"
        suffix += 1

    cursor = connection.execute(
        """
        INSERT INTO users (username, public_key, encrypted_private_key)
        VALUES (?, ?, ?)
        """,
        (username, sqlite3.Binary(public_key), sqlite3.Binary(private_key)),
    )
    return int(cursor.lastrowid)


def _migrate_legacy_files(
    connection: sqlite3.Connection,
    table_names: set[str],
    legacy_owner_id: int | None,
) -> None:
    if "encrypted_files" not in table_names:
        return

    columns = {
        str(row["name"])
        for row in connection.execute("PRAGMA table_info(encrypted_files)").fetchall()
    }
    if "owner_id" in columns:
        return

    if "encrypted_files_legacy" in table_names:
        raise RuntimeError(
            "Both legacy and current encrypted-file tables exist; back up the database "
            "and resolve the schema before continuing."
        )
    if legacy_owner_id is None:
        has_records = connection.execute(
            "SELECT 1 FROM encrypted_files LIMIT 1"
        ).fetchone()
        if has_records:
            raise RuntimeError(
                "Existing encrypted files have no associated RSA key pair. "
                "Restore the legacy keypair before migrating this database."
            )
        connection.execute("DROP TABLE encrypted_files")
        return

    connection.execute("ALTER TABLE encrypted_files RENAME TO encrypted_files_legacy")


def initialize_database(database_path: str | Path = DEFAULT_DATABASE_PATH) -> None:
    """Create the user/file schema and migrate the former single-keypair database."""
    with _connect(database_path) as connection:
        table_names = _table_names(connection)
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                public_key BLOB NOT NULL,
                encrypted_private_key BLOB NOT NULL,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            )
            """
        )

        legacy_owner_id = _migrate_legacy_keypair(connection, table_names)
        _migrate_legacy_files(connection, table_names, legacy_owner_id)

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS encrypted_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                original_name TEXT NOT NULL,
                encrypted_content BLOB NOT NULL,
                encrypted_aes_key BLOB NOT NULL,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0)
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_encrypted_files_owner_created
            ON encrypted_files(owner_id, created_at)
            """
        )

        if "encrypted_files_legacy" in _table_names(connection):
            if legacy_owner_id is None:
                raise RuntimeError(
                    "The legacy RSA keypair could not be mapped to an account."
                )
            connection.execute(
                """
                INSERT OR IGNORE INTO encrypted_files (
                    id, owner_id, original_name, encrypted_content,
                    encrypted_aes_key, created_at, size_bytes
                )
                SELECT id, ?, original_name, encrypted_content,
                       encrypted_aes_key, created_at, size_bytes
                FROM encrypted_files_legacy
                """,
                (legacy_owner_id,),
            )
            connection.execute("DROP TABLE encrypted_files_legacy")


def list_users(database_path: str | Path = DEFAULT_DATABASE_PATH) -> list[str]:
    initialize_database(database_path)
    with _connect(database_path) as connection:
        rows = connection.execute(
            "SELECT username FROM users ORDER BY username COLLATE NOCASE"
        ).fetchall()
    return [str(row["username"]) for row in rows]


def get_user(
    username: str,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> UserRecord | None:
    initialize_database(database_path)
    with _connect(database_path) as connection:
        row = connection.execute(
            """
            SELECT id, username, public_key, encrypted_private_key
            FROM users
            WHERE username = ? COLLATE NOCASE
            """,
            (username,),
        ).fetchone()
    if row is None:
        return None
    return UserRecord(
        id=int(row["id"]),
        username=str(row["username"]),
        public_key=bytes(row["public_key"]),
        encrypted_private_key=bytes(row["encrypted_private_key"]),
    )


def get_user_by_id(
    user_id: int,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> UserRecord | None:
    initialize_database(database_path)
    with _connect(database_path) as connection:
        row = connection.execute(
            """
            SELECT id, username, public_key, encrypted_private_key
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()
    if row is None:
        return None
    return UserRecord(
        id=int(row["id"]),
        username=str(row["username"]),
        public_key=bytes(row["public_key"]),
        encrypted_private_key=bytes(row["encrypted_private_key"]),
    )


def create_user(
    username: str,
    public_key: bytes,
    encrypted_private_key: bytes,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> int:
    initialize_database(database_path)
    try:
        with _connect(database_path) as connection:
            cursor = connection.execute(
                """
                INSERT INTO users (username, public_key, encrypted_private_key)
                VALUES (?, ?, ?)
                """,
                (
                    username,
                    sqlite3.Binary(public_key),
                    sqlite3.Binary(encrypted_private_key),
                ),
            )
            return int(cursor.lastrowid)
    except sqlite3.IntegrityError as exc:
        raise ValueError(f"The username '{username}' is already registered.") from exc


def save_encrypted_file(
    owner_id: int,
    original_name: str,
    encrypted_content: bytes,
    encrypted_aes_key: bytes,
    original_size: int,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> int:
    initialize_database(database_path)
    with _connect(database_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO encrypted_files (
                owner_id, original_name, encrypted_content,
                encrypted_aes_key, size_bytes
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                owner_id,
                original_name,
                sqlite3.Binary(encrypted_content),
                sqlite3.Binary(encrypted_aes_key),
                original_size,
            ),
        )
        return int(cursor.lastrowid)


def list_encrypted_files(
    owner_id: int,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> list[StoredFileSummary]:
    initialize_database(database_path)
    with _connect(database_path) as connection:
        rows = connection.execute(
            """
            SELECT id, owner_id, original_name, created_at, size_bytes
            FROM encrypted_files
            WHERE owner_id = ?
            ORDER BY created_at DESC, id DESC
            """,
            (owner_id,),
        ).fetchall()
    return [
        StoredFileSummary(
            id=int(row["id"]),
            owner_id=int(row["owner_id"]),
            original_name=str(row["original_name"]),
            created_at=str(row["created_at"]),
            size_bytes=int(row["size_bytes"]),
        )
        for row in rows
    ]


def get_encrypted_file(
    file_id: int,
    owner_id: int,
    database_path: str | Path = DEFAULT_DATABASE_PATH,
) -> StoredFile | None:
    initialize_database(database_path)
    with _connect(database_path) as connection:
        row = connection.execute(
            """
            SELECT id, owner_id, original_name, created_at, size_bytes,
                   encrypted_content, encrypted_aes_key
            FROM encrypted_files
            WHERE id = ? AND owner_id = ?
            """,
            (file_id, owner_id),
        ).fetchone()
    if row is None:
        return None
    return StoredFile(
        id=int(row["id"]),
        owner_id=int(row["owner_id"]),
        original_name=str(row["original_name"]),
        created_at=str(row["created_at"]),
        size_bytes=int(row["size_bytes"]),
        encrypted_content=bytes(row["encrypted_content"]),
        encrypted_aes_key=bytes(row["encrypted_aes_key"]),
    )
