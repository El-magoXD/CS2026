from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class RegisterRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8, max_length=1024)
    public_key: str = Field(min_length=1, max_length=2048)
    encrypted_private_key: str = Field(min_length=1, max_length=8192)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


class SessionResponse(BaseModel):
    access_token: str
    user_id: int
    username: str
    public_key: str
    encrypted_private_key: str


class UserSummary(BaseModel):
    id: int
    username: str
    public_key: str


class FileSummary(BaseModel):
    id: int
    original_name: str
    created_at: datetime
    size_bytes: int


class FileDetails(FileSummary):
    encrypted_aes_key: str


class CreateShareRequest(BaseModel):
    recipient_username: str = Field(min_length=1, max_length=64)
    encrypted_aes_key: str = Field(min_length=1, max_length=8192)


class ShareSummary(BaseModel):
    id: int
    file_id: int
    original_name: str
    shared_by: str
    created_at: datetime
    size_bytes: int
