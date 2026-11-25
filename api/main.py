from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Union

from Crypto.PublicKey import RSA
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.database import Base, create_database_engine, create_session_factory, get_session
from api.models import ApiSession, EncryptedFile, FileShare, User
from api.schemas import (
    CreateShareRequest,
    FileDetails,
    FileSummary,
    LoginRequest,
    RegisterRequest,
    SessionResponse,
    ShareSummary,
    UserSummary,
)


SESSION_LIFETIME = timedelta(hours=12)
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1


def _decode_b64(value: str, label: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid {label} encoding.") from exc


def _hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=64,
    )


def _normalize_username(username: str) -> str:
    return username.strip().casefold()


def create_app(database_url: str | None = None) -> FastAPI:
    engine = create_database_engine(database_url)
    session_factory = create_session_factory(engine)
    Base.metadata.create_all(engine)

    app = FastAPI(title="CS2026 Secure File API", version="1.0.0")
    app.state.session_factory = session_factory

    def database_session():
        yield from get_session(session_factory)

    def current_user(
        authorization: Optional[str] = Header(None),
        db: Session = Depends(database_session),
    ) -> User:
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.casefold() != "bearer" or not token:
            raise HTTPException(status_code=401, detail="Authentication required.")
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        stored_session = db.get(ApiSession, token_hash)
        now = datetime.now(timezone.utc)
        if stored_session is None:
            raise HTTPException(status_code=401, detail="Session is invalid or expired.")
        expires_at = stored_session.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= now:
            db.delete(stored_session)
            db.commit()
            raise HTTPException(status_code=401, detail="Session is invalid or expired.")
        user = db.get(User, stored_session.user_id)
        if user is None:
            raise HTTPException(status_code=401, detail="Session is invalid or expired.")
        return user

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
    def register(
        payload: RegisterRequest,
        db: Session = Depends(database_session),
    ) -> Dict[str, Union[int, str]]:
        username = _normalize_username(payload.username)
        if not username:
            raise HTTPException(status_code=400, detail="Username cannot be empty.")
        try:
            public_key = RSA.import_key(payload.public_key)
        except (ValueError, IndexError, TypeError) as exc:
            raise HTTPException(status_code=400, detail="Invalid RSA public key.") from exc
        if public_key.has_private() or public_key.size_in_bits() != 2048:
            raise HTTPException(status_code=400, detail="A 2048-bit public RSA key is required.")

        encrypted_private_key = _decode_b64(
            payload.encrypted_private_key,
            "encrypted private key",
        )
        if len(encrypted_private_key) < 48:
            raise HTTPException(status_code=400, detail="Encrypted private key is incomplete.")

        password_salt = secrets.token_bytes(16)
        user = User(
            username=username,
            password_salt=password_salt,
            password_hash=_hash_password(payload.password, password_salt),
            public_key=public_key.export_key(format="PEM").decode("ascii"),
            encrypted_private_key=encrypted_private_key,
        )
        db.add(user)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail="Username is already registered.") from exc
        return {"id": user.id, "username": user.username}

    @app.post("/api/auth/login", response_model=SessionResponse)
    def login(
        payload: LoginRequest,
        db: Session = Depends(database_session),
    ) -> SessionResponse:
        username = _normalize_username(payload.username)
        user = db.scalar(select(User).where(User.username == username))
        invalid_credentials = HTTPException(
            status_code=401,
            detail="Incorrect username or password.",
        )
        if user is None:
            raise invalid_credentials
        expected_hash = _hash_password(payload.password, user.password_salt)
        if not hmac.compare_digest(expected_hash, user.password_hash):
            raise invalid_credentials

        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        db.add(
            ApiSession(
                token_hash=token_hash,
                user_id=user.id,
                expires_at=datetime.now(timezone.utc) + SESSION_LIFETIME,
            )
        )
        db.commit()
        return SessionResponse(
            access_token=token,
            user_id=user.id,
            username=user.username,
            public_key=user.public_key,
            encrypted_private_key=base64.b64encode(user.encrypted_private_key).decode("ascii"),
        )

    @app.post(
        "/api/auth/logout",
        status_code=status.HTTP_204_NO_CONTENT,
        dependencies=[Depends(current_user)],
    )
    def logout(
        authorization: str = Header(...),
        db: Session = Depends(database_session),
    ) -> Response:
        _, _, token = authorization.partition(" ")
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        stored_session = db.get(ApiSession, token_hash)
        if stored_session is not None:
            db.delete(stored_session)
            db.commit()
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @app.get("/api/users/search", response_model=list[UserSummary])
    def search_users(
        user: User = Depends(current_user),
        db: Session = Depends(database_session),
        query: str = Query(min_length=1, max_length=64),
    ) -> list[UserSummary]:
        normalized_query = _normalize_username(query)
        rows = db.scalars(
            select(User)
            .where(User.username == normalized_query, User.id != user.id)
            .order_by(User.username)
            .limit(20)
        ).all()
        return [
            UserSummary(id=row.id, username=row.username, public_key=row.public_key)
            for row in rows
        ]

    @app.get("/api/files", response_model=list[FileSummary])
    def list_files(
        user: User = Depends(current_user),
        db: Session = Depends(database_session),
    ) -> list[FileSummary]:
        files = db.scalars(
            select(EncryptedFile)
            .where(EncryptedFile.owner_id == user.id)
            .order_by(EncryptedFile.created_at.desc(), EncryptedFile.id.desc())
        ).all()
        return [
            FileSummary(
                id=file.id,
                original_name=file.original_name,
                created_at=file.created_at,
                size_bytes=file.size_bytes,
            )
            for file in files
        ]

    @app.post("/api/files", status_code=status.HTTP_201_CREATED)
    def upload_file(
        user: User = Depends(current_user),
        db: Session = Depends(database_session),
        original_name: str = Query(min_length=1, max_length=255),
        size_bytes: int = Query(ge=0, le=2_147_483_647),
        encrypted_aes_key: str = Header(
            ...,
            alias="X-Encrypted-AES-Key",
            min_length=1,
            max_length=8192,
        ),
        body: bytes = Body(..., media_type="application/octet-stream"),
    ) -> dict[str, int]:
        if not body or len(body) < 32:
            raise HTTPException(status_code=400, detail="Encrypted file is too short.")
        wrapped_key = _decode_b64(encrypted_aes_key, "encrypted AES key")
        try:
            if len(wrapped_key) != 256:
                raise ValueError("unexpected RSA key length")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid encrypted AES key.") from exc
        file = EncryptedFile(
            owner_id=user.id,
            original_name=original_name,
            encrypted_content=body,
            encrypted_aes_key=wrapped_key,
            size_bytes=size_bytes,
        )
        db.add(file)
        db.commit()
        return {"id": file.id}

    @app.get("/api/files/{file_id}", response_model=FileDetails)
    def get_file(
        file_id: int,
        user: User = Depends(current_user),
        db: Session = Depends(database_session),
    ) -> FileDetails:
        file = db.scalar(
            select(EncryptedFile).where(
                EncryptedFile.id == file_id,
                EncryptedFile.owner_id == user.id,
            )
        )
        if file is None:
            raise HTTPException(status_code=404, detail="File not found.")
        return FileDetails(
            id=file.id,
            original_name=file.original_name,
            created_at=file.created_at,
            size_bytes=file.size_bytes,
            encrypted_aes_key=base64.b64encode(file.encrypted_aes_key).decode("ascii"),
        )

    @app.get("/api/files/{file_id}/content")
    def get_file_content(
        file_id: int,
        user: User = Depends(current_user),
        db: Session = Depends(database_session),
    ) -> Response:
        file = db.scalar(
            select(EncryptedFile).where(
                EncryptedFile.id == file_id,
                EncryptedFile.owner_id == user.id,
            )
        )
        if file is None:
            raise HTTPException(status_code=404, detail="File not found.")
        return Response(content=file.encrypted_content, media_type="application/octet-stream")

    @app.post("/api/files/{file_id}/shares", status_code=status.HTTP_201_CREATED)
    def share_file(
        file_id: int,
        payload: CreateShareRequest,
        user: User = Depends(current_user),
        db: Session = Depends(database_session),
    ) -> dict[str, int]:
        file = db.scalar(
            select(EncryptedFile).where(
                EncryptedFile.id == file_id,
                EncryptedFile.owner_id == user.id,
            )
        )
        if file is None:
            raise HTTPException(status_code=404, detail="File not found.")
        recipient_name = _normalize_username(payload.recipient_username)
        recipient = db.scalar(select(User).where(User.username == recipient_name))
        if recipient is None:
            raise HTTPException(status_code=404, detail="Recipient account not found.")
        if recipient.id == user.id:
            raise HTTPException(status_code=400, detail="You cannot share a file with yourself.")
        wrapped_key = _decode_b64(payload.encrypted_aes_key, "encrypted AES key")
        if len(wrapped_key) != 256:
            raise HTTPException(status_code=400, detail="Invalid encrypted AES key.")

        share = db.scalar(
            select(FileShare).where(
                FileShare.file_id == file.id,
                FileShare.recipient_id == recipient.id,
            )
        )
        if share is None:
            share = FileShare(
                file_id=file.id,
                recipient_id=recipient.id,
                encrypted_aes_key=wrapped_key,
            )
            db.add(share)
        else:
            share.encrypted_aes_key = wrapped_key
        db.commit()
        return {"id": share.id}

    @app.get("/api/shares/received", response_model=list[ShareSummary])
    def list_received_shares(
        user: User = Depends(current_user),
        db: Session = Depends(database_session),
    ) -> list[ShareSummary]:
        rows = db.execute(
            select(FileShare, EncryptedFile, User)
            .join(EncryptedFile, FileShare.file_id == EncryptedFile.id)
            .join(User, EncryptedFile.owner_id == User.id)
            .where(FileShare.recipient_id == user.id)
            .order_by(FileShare.created_at.desc(), FileShare.id.desc())
        ).all()
        return [
            ShareSummary(
                id=share.id,
                file_id=file.id,
                original_name=file.original_name,
                shared_by=owner.username,
                created_at=share.created_at,
                size_bytes=file.size_bytes,
            )
            for share, file, owner in rows
        ]

    @app.get("/api/shares/{share_id}/key")
    def get_shared_key(
        share_id: int,
        user: User = Depends(current_user),
        db: Session = Depends(database_session),
    ) -> dict[str, str]:
        share = db.scalar(
            select(FileShare).where(
                FileShare.id == share_id,
                FileShare.recipient_id == user.id,
            )
        )
        if share is None:
            raise HTTPException(status_code=404, detail="Shared file not found.")
        return {
            "encrypted_aes_key": base64.b64encode(share.encrypted_aes_key).decode("ascii")
        }

    @app.get("/api/shares/{share_id}/content")
    def get_shared_content(
        share_id: int,
        user: User = Depends(current_user),
        db: Session = Depends(database_session),
    ) -> Response:
        share = db.scalar(
            select(FileShare)
            .where(FileShare.id == share_id, FileShare.recipient_id == user.id)
        )
        if share is None:
            raise HTTPException(status_code=404, detail="Shared file not found.")
        file = db.get(EncryptedFile, share.file_id)
        if file is None:
            raise HTTPException(status_code=404, detail="Shared file not found.")
        return Response(content=file.encrypted_content, media_type="application/octet-stream")

    @app.delete("/api/files/{file_id}/shares", status_code=status.HTTP_204_NO_CONTENT)
    def revoke_share(
        file_id: int,
        recipient_username: str = Query(min_length=1, max_length=64),
        user: User = Depends(current_user),
        db: Session = Depends(database_session),
    ) -> Response:
        recipient_name = _normalize_username(recipient_username)
        share = db.scalar(
            select(FileShare)
            .join(EncryptedFile, FileShare.file_id == EncryptedFile.id)
            .join(User, FileShare.recipient_id == User.id)
            .where(
                FileShare.file_id == file_id,
                EncryptedFile.owner_id == user.id,
                User.username == recipient_name,
            )
        )
        if share is None:
            raise HTTPException(status_code=404, detail="Share not found.")
        db.delete(share)
        db.commit()
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    return app


app = create_app()
