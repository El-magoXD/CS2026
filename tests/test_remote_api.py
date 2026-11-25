from __future__ import annotations

import base64
import unittest
from unittest.mock import patch

from Crypto.PublicKey import RSA
from fastapi.testclient import TestClient

from api.client import _client
from api.main import create_app
from crypto.aes import decrypt_bytes, encrypt_bytes
from crypto.passwords import encrypt_private_key
from crypto.rsa import decrypt_with_private, encrypt_with_public, generate_rsa_keys


class RemoteApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(create_app("sqlite:///:memory:"))
        self.users: dict[str, tuple[RSA.RsaKey, str]] = {}

    def tearDown(self) -> None:
        self.client.close()

    def _register_and_login(self, username: str) -> tuple[str, RSA.RsaKey]:
        password = f"{username}-test-password"
        private_key, public_key = generate_rsa_keys()
        self.users[username] = (private_key, password)
        encrypted_private_key = encrypt_private_key(private_key, password)
        response = self.client.post(
            "/api/auth/register",
            json={
                "username": username,
                "password": password,
                "public_key": public_key.export_key(format="PEM").decode("ascii"),
                "encrypted_private_key": base64.b64encode(
                    encrypted_private_key
                ).decode("ascii"),
            },
        )
        self.assertEqual(response.status_code, 201, response.text)

        login = self.client.post(
            "/api/auth/login",
            json={"username": username, "password": password},
        )
        self.assertEqual(login.status_code, 200, login.text)
        return login.json()["access_token"], private_key

    def test_share_rewraps_file_key_for_recipient_and_enforces_access(self) -> None:
        alice_token, alice_private_key = self._register_and_login("alice")
        bob_token, bob_private_key = self._register_and_login("bob")
        alice_headers = {"Authorization": f"Bearer {alice_token}"}
        bob_headers = {"Authorization": f"Bearer {bob_token}"}

        plaintext = b"private file bytes\x00\x01"
        aes_key = b"0123456789abcdef"
        nonce, tag, ciphertext = encrypt_bytes(plaintext, aes_key)
        alice_wrapped_key = encrypt_with_public(
            aes_key,
            alice_private_key.public_key(),
        )
        upload = self.client.post(
            "/api/files",
            headers={
                **alice_headers,
                "Content-Type": "application/octet-stream",
                "X-Encrypted-AES-Key": base64.b64encode(alice_wrapped_key).decode("ascii"),
            },
            params={
                "original_name": "secret.bin",
                "size_bytes": len(plaintext),
            },
            content=nonce + tag + ciphertext,
        )
        self.assertEqual(upload.status_code, 201, upload.text)
        file_id = upload.json()["id"]

        denied = self.client.get(f"/api/files/{file_id}/content", headers=bob_headers)
        self.assertEqual(denied.status_code, 404)
        encrypted_for_owner = self.client.get(
            f"/api/files/{file_id}/content",
            headers=alice_headers,
        )
        self.assertEqual(encrypted_for_owner.status_code, 200)
        self.assertNotIn(plaintext, encrypted_for_owner.content)

        bob_public_key = bob_private_key.public_key()
        bob_wrapped_key = encrypt_with_public(aes_key, bob_public_key)
        share = self.client.post(
            f"/api/files/{file_id}/shares",
            headers=alice_headers,
            json={
                "recipient_username": "bob",
                "encrypted_aes_key": base64.b64encode(bob_wrapped_key).decode("ascii"),
            },
        )
        self.assertEqual(share.status_code, 201, share.text)
        share_id = share.json()["id"]

        received = self.client.get("/api/shares/received", headers=bob_headers)
        self.assertEqual(received.status_code, 200, received.text)
        self.assertEqual(received.json()[0]["original_name"], "secret.bin")
        key_response = self.client.get(
            f"/api/shares/{share_id}/key",
            headers=bob_headers,
        )
        shared_content = self.client.get(
            f"/api/shares/{share_id}/content",
            headers=bob_headers,
        )
        recovered_key = decrypt_with_private(
            base64.b64decode(key_response.json()["encrypted_aes_key"]),
            bob_private_key,
        )
        recovered = decrypt_bytes(
            shared_content.content[32:],
            recovered_key,
            shared_content.content[:16],
            shared_content.content[16:32],
        )
        self.assertEqual(recovered, plaintext)

        revoked = self.client.delete(
            f"/api/files/{file_id}/shares",
            headers=alice_headers,
            params={"recipient_username": "bob"},
        )
        self.assertEqual(revoked.status_code, 204)
        self.assertEqual(
            self.client.get(
                f"/api/shares/{share_id}/content",
                headers=bob_headers,
            ).status_code,
            404,
        )

    def test_login_rejects_wrong_password_and_requires_bearer_token(self) -> None:
        token, _ = self._register_and_login("alice")
        wrong_password = self.client.post(
            "/api/auth/login",
            json={"username": "alice", "password": "not-the-password"},
        )
        self.assertEqual(wrong_password.status_code, 401)
        self.assertEqual(self.client.get("/api/files").status_code, 401)
        logout = self.client.post(
            "/api/auth/logout",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(logout.status_code, 204)
        self.assertEqual(
            self.client.get(
                "/api/files",
                headers={"Authorization": f"Bearer {token}"},
            ).status_code,
            401,
        )

    def test_remote_client_refuses_plain_http_outside_localhost(self) -> None:
        with patch("api.client.API_BASE_URL", "http://magocloud.ddns.net"):
            with self.assertRaisesRegex(ValueError, "HTTPS"):
                _client()

        with patch("api.client.API_BASE_URL", "http://127.0.0.1:8000"):
            client = _client()
            client.close()


if __name__ == "__main__":
    unittest.main()
