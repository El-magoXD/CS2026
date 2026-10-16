from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from crypto.aes import encrypt_bytes
from crypto.passwords import encrypt_private_key
from crypto.rsa import encrypt_with_public, generate_rsa_keys
from database.database import (
    get_encrypted_file,
    initialize_database,
    list_encrypted_files,
    list_users,
)
from services.file_service import (
    authenticate_user,
    decrypt_file_from_database,
    encrypt_file_to_database,
    register_user,
)


class SQLiteFileServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.database_path = self.root / "data" / "storage.sqlite3"
        self.source = self.root / "sample.jpg"
        self.source_bytes = b"sample image bytes\x00\x01\x02"
        self.source.write_bytes(self.source_bytes)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_login_unlocks_private_key_once_and_file_round_trips(self) -> None:
        user_id = register_user("alice", "correct horse battery staple", self.database_path)
        session = authenticate_user("alice", "correct horse battery staple", self.database_path)
        file_id = encrypt_file_to_database(self.source, user_id, self.database_path)

        stored_file = get_encrypted_file(file_id, user_id, self.database_path)
        entries = list_encrypted_files(user_id, self.database_path)
        self.assertIsNotNone(stored_file)
        assert stored_file is not None
        self.assertNotIn(self.source_bytes, stored_file.encrypted_content)
        self.assertEqual(stored_file.original_name, self.source.name)
        self.assertEqual(stored_file.size_bytes, len(self.source_bytes))
        self.assertEqual(len(stored_file.encrypted_aes_key), 256)
        self.assertEqual([entry.id for entry in entries], [file_id])

        destination = self.root / "restored" / "sample.jpg"
        decrypt_file_from_database(
            file_id,
            session.id,
            session.private_key,
            destination,
            self.database_path,
        )
        self.assertEqual(destination.read_bytes(), self.source_bytes)

    def test_password_is_verified_at_login_and_username_is_case_insensitive(self) -> None:
        register_user("Alice", "correct password", self.database_path)

        session = authenticate_user("alice", "correct password", self.database_path)
        self.assertEqual(session.username, "Alice")
        with self.assertRaisesRegex(ValueError, "No se pudo desbloquear"):
            authenticate_user("alice", "wrong password", self.database_path)
        self.assertEqual(list_users(self.database_path), ["Alice"])

    def test_files_are_isolated_by_user(self) -> None:
        alice_id = register_user("alice", "alice password", self.database_path)
        bob_id = register_user("bob", "bob password", self.database_path)
        alice_session = authenticate_user("alice", "alice password", self.database_path)
        file_id = encrypt_file_to_database(self.source, alice_id, self.database_path)

        self.assertEqual(len(list_encrypted_files(bob_id, self.database_path)), 0)
        with self.assertRaises(FileNotFoundError):
            decrypt_file_from_database(
                file_id,
                bob_id,
                authenticate_user("bob", "bob password", self.database_path).private_key,
                self.root / "unauthorized.jpg",
                self.database_path,
            )
        self.assertEqual(
            len(list_encrypted_files(alice_session.id, self.database_path)),
            1,
        )

    def test_existing_single_user_database_is_migrated_without_losing_files(self) -> None:
        private_key, public_key = generate_rsa_keys()
        encrypted_private_key = encrypt_private_key(private_key, "legacy password")
        aes_key = b"0123456789abcdef"
        nonce, tag, ciphertext = encrypt_bytes(self.source_bytes, aes_key)
        encrypted_aes_key = encrypt_with_public(aes_key, public_key)

        self.database_path.parent.mkdir(parents=True)
        connection = sqlite3.connect(self.database_path)
        connection.executescript(
            """
            CREATE TABLE keypairs (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                public_key BLOB NOT NULL,
                encrypted_private_key BLOB NOT NULL,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            );
            CREATE TABLE encrypted_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_name TEXT NOT NULL,
                encrypted_content BLOB NOT NULL,
                encrypted_aes_key BLOB NOT NULL,
                keypair_id INTEGER NOT NULL DEFAULT 1 REFERENCES keypairs(id),
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0)
            );
            """
        )
        connection.execute(
            "INSERT INTO keypairs (id, public_key, encrypted_private_key) VALUES (1, ?, ?)",
            (public_key.export_key(format="PEM"), encrypted_private_key),
        )
        connection.execute(
            """
            INSERT INTO encrypted_files
                (original_name, encrypted_content, encrypted_aes_key, size_bytes)
            VALUES (?, ?, ?, ?)
            """,
            (
                self.source.name,
                nonce + tag + ciphertext,
                encrypted_aes_key,
                len(self.source_bytes),
            ),
        )
        connection.commit()
        connection.close()

        initialize_database(self.database_path)
        self.assertEqual(list_users(self.database_path), ["usuario"])
        session = authenticate_user("usuario", "legacy password", self.database_path)
        files = list_encrypted_files(session.id, self.database_path)
        self.assertEqual(len(files), 1)

        destination = self.root / "migrated.jpg"
        decrypt_file_from_database(
            files[0].id,
            session.id,
            session.private_key,
            destination,
            self.database_path,
        )
        self.assertEqual(destination.read_bytes(), self.source_bytes)

    def test_duplicate_username_is_rejected(self) -> None:
        register_user("alice", "first password", self.database_path)
        with self.assertRaisesRegex(ValueError, "already registered"):
            register_user("ALICE", "second password", self.database_path)


if __name__ == "__main__":
    unittest.main()
