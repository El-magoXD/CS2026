from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, String, UniqueConstraint
from sqlalchemy.dialects.mysql import LONGBLOB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.database import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_salt: Mapped[bytes] = mapped_column(LargeBinary(16))
    password_hash: Mapped[bytes] = mapped_column(LargeBinary(64))
    public_key: Mapped[str] = mapped_column(String(2048))
    encrypted_private_key: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    files: Mapped[list[EncryptedFile]] = relationship(
        back_populates="owner",
        cascade="all, delete-orphan",
    )


class ApiSession(Base):
    __tablename__ = "api_sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class EncryptedFile(Base):
    __tablename__ = "encrypted_files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    original_name: Mapped[str] = mapped_column(String(255))
    encrypted_content: Mapped[bytes] = mapped_column(
        LargeBinary().with_variant(LONGBLOB(), "mysql")
    )
    encrypted_aes_key: Mapped[bytes] = mapped_column(LargeBinary(1024))
    size_bytes: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    owner: Mapped[User] = relationship(back_populates="files")
    shares: Mapped[list[FileShare]] = relationship(
        back_populates="file",
        cascade="all, delete-orphan",
    )


class FileShare(Base):
    __tablename__ = "file_shares"
    __table_args__ = (
        UniqueConstraint("file_id", "recipient_id", name="uq_file_share_recipient"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    file_id: Mapped[int] = mapped_column(ForeignKey("encrypted_files.id", ondelete="CASCADE"))
    recipient_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    encrypted_aes_key: Mapped[bytes] = mapped_column(LargeBinary(1024))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utc_now)

    file: Mapped[EncryptedFile] = relationship(back_populates="shares")
    recipient: Mapped[User] = relationship()
