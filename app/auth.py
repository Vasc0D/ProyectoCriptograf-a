"""Password and session-token helpers.

Passwords are hashed with Argon2id.  Session tokens are short-lived, signed
capabilities; the server never places a password or private key in a token.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHash, VerificationError, VerifyMismatchError


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


# Argon2id defaults are intentionally memory-hard.  Environment overrides are
# bounded so a malformed deployment value cannot silently select an unsafe
# configuration or exhaust the host.
ARGON2_TIME_COST = _bounded_int("ARGON2_TIME_COST", 3, 2, 10)
ARGON2_MEMORY_COST_KIB = _bounded_int("ARGON2_MEMORY_COST_KIB", 65536, 16 * 1024, 512 * 1024)
ARGON2_PARALLELISM = _bounded_int("ARGON2_PARALLELISM", 4, 1, 8)
PASSWORD_HASHER = PasswordHasher(
    type=Type.ID,
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST_KIB,
    parallelism=ARGON2_PARALLELISM,
)
TOKEN_TTL_SECONDS = _bounded_int("SESSION_TTL_SECONDS", 43200, 300, 7 * 24 * 60 * 60)
_PROCESS_SECRET = secrets.token_bytes(32)


def _secret() -> bytes:
    configured = os.environ.get("SESSION_SECRET")
    if configured:
        if len(configured.encode("utf-8")) < 32 or configured.startswith("replace-with-"):
            raise RuntimeError("SESSION_SECRET must contain at least 32 non-placeholder bytes")
        return hashlib.sha256(configured.encode("utf-8")).digest()
    return _PROCESS_SECRET


def hash_password(password: str) -> str:
    return PASSWORD_HASHER.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return PASSWORD_HASHER.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False


def maybe_rehash(password_hash: str, password: str) -> str | None:
    """Return an upgraded hash when Argon2 parameters changed."""

    if not verify_password(password_hash, password):
        return None
    try:
        return PASSWORD_HASHER.hash(password) if PASSWORD_HASHER.check_needs_rehash(password_hash) else None
    except (InvalidHash, VerificationError):
        return None


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    if not value or len(value) > 4096:
        raise ValueError("invalid token")
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def create_token(username: str, ttl_seconds: int | None = None) -> str:
    now = int(time.time())
    ttl = TOKEN_TTL_SECONDS if ttl_seconds is None else max(60, int(ttl_seconds))
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + ttl,
        "jti": secrets.token_urlsafe(12),
    }
    encoded_payload = _b64encode(
        json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )
    signature = hmac.new(_secret(), encoded_payload.encode("ascii"), hashlib.sha256).digest()
    return f"{encoded_payload}.{_b64encode(signature)}"


def verify_token(token: str) -> dict[str, Any]:
    if not isinstance(token, str) or len(token) > 8192:
        raise ValueError("invalid token")
    try:
        encoded_payload, encoded_signature = token.split(".", 1)
        expected = hmac.new(
            _secret(), encoded_payload.encode("ascii"), hashlib.sha256
        ).digest()
        actual = _b64decode(encoded_signature)
        if not hmac.compare_digest(actual, expected):
            raise ValueError("invalid token")
        payload = json.loads(_b64decode(encoded_payload).decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("invalid token")
        username = payload.get("sub")
        exp = payload.get("exp")
        iat = payload.get("iat")
        if not isinstance(username, str) or not username:
            raise ValueError("invalid token")
        if not isinstance(exp, int) or not isinstance(iat, int):
            raise ValueError("invalid token")
        now = int(time.time())
        if exp <= now or iat > now + 60 or exp - iat > 31 * 24 * 60 * 60:
            raise ValueError("expired token")
        return payload
    except (
        ValueError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
        binascii.Error,
    ):
        raise ValueError("invalid token") from None


def token_from_authorization(header: str | None) -> str | None:
    if not header:
        return None
    scheme, separator, value = header.partition(" ")
    if not separator or scheme.lower() != "bearer" or not value:
        return None
    return value.strip()
