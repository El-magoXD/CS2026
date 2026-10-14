from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from crypto.passwords import encrypt_private_key
from crypto.rsa import generate_rsa_keys
from database.database import get_encrypted_file, get_keypair, list_encrypted_files
from services.file_service import decrypt_file_from_database, encrypt_file_to_database


class SQLiteFileServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.database_path = self.root / "data" / "storage.sqlite3"
        self.legacy_public_key = self.root / "legacy" / "rsa_public.pem"
        self.legacy_private_key = self.root / "legacy" / "rsa_private.enc"
        self.source = self.root / "sample.jpg"
        self.source_bytes = b"sample image bytes\x00\x01\x02"
        self.source.write_bytes(self.source_bytes)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_encrypt_persists_ciphertext_and_decrypts_after_reload(self) -> None:
        file_id = encrypt_file_to_database(
            self.source,
            "correct horse battery staple",
            self.database_path,
            self.legacy_public_key,
            self.legacy_private_key,
        )

        stored_file = get_encrypted_file(file_id, self.database_path)
        keypair = get_keypair(self.database_path)
        entries = list_encrypted_files(self.database_path)

        self.assertIsNotNone(stored_file)
        self.assertIsNotNone(keypair)
        assert stored_file is not None
        assert keypair is not None
        self.assertNotIn(self.source_bytes, stored_file.encrypted_content)
        self.assertEqual(stored_file.original_name, self.source.name)
        self.assertEqual(stored_file.size_bytes, len(self.source_bytes))
        self.assertEqual(len(stored_file.encrypted_aes_key), 256)
        self.assertNotIn(self.source_bytes, keypair.encrypted_private_key)
        self.assertEqual([entry.id for entry in entries], [file_id])

        destination = self.root / "restored" / "sample.jpg"
        decrypt_file_from_database(
            file_id,
            "correct horse battery staple",
            destination,
            self.database_path,
        )
        self.assertEqual(destination.read_bytes(), self.source_bytes)

    def test_wrong_password_does_not_write_plaintext(self) -> None:
        file_id = encrypt_file_to_database(
            self.source,
            "correct password",
            self.database_path,
            self.legacy_public_key,
            self.legacy_private_key,
        )
        destination = self.root / "must-not-exist.jpg"

        with self.assertRaises(ValueError):
            decrypt_file_from_database(
                file_id,
                "incorrect password",
                destination,
                self.database_path,
            )

        self.assertFalse(destination.exists())

    def test_existing_file_keypair_is_imported_to_database(self) -> None:
        self.legacy_public_key.parent.mkdir(parents=True)
        private_key, public_key = generate_rsa_keys()
        self.legacy_public_key.write_bytes(public_key.export_key(format="PEM"))
        self.legacy_private_key.write_bytes(
            encrypt_private_key(private_key, "legacy password")
        )

        file_id = encrypt_file_to_database(
            self.source,
            "legacy password",
            self.database_path,
            self.legacy_public_key,
            self.legacy_private_key,
        )

        self.assertIsNotNone(get_keypair(self.database_path))
        destination = self.root / "legacy-restored.jpg"
        decrypt_file_from_database(
            file_id,
            "legacy password",
            destination,
            self.database_path,
        )
        self.assertEqual(destination.read_bytes(), self.source_bytes)

    def test_encryption_refuses_wrong_password_for_existing_database_key(self) -> None:
        encrypt_file_to_database(
            self.source,
            "database password",
            self.database_path,
            self.legacy_public_key,
            self.legacy_private_key,
        )

        with self.assertRaises(ValueError):
            encrypt_file_to_database(
                self.source,
                "wrong password",
                self.database_path,
                self.legacy_public_key,
                self.legacy_private_key,
            )

        self.assertEqual(len(list_encrypted_files(self.database_path)), 1)


if __name__ == "__main__":
    unittest.main()
