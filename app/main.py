"""FastAPI entry point for the encrypted messaging service.

Run locally with::

    uvicorn app.main:app --reload

The HTTP API handles account and public-key operations.  WebSocket clients
send only signed/encrypted envelopes; the server routes and queues those
envelopes without decrypting or storing plaintext.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import logging
import os
import re
import secrets
import threading
import time
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import auth, db


LOGGER = logging.getLogger("messaging")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")
MAX_WEBSOCKET_BYTES = 128 * 1024
MAX_ENVELOPE_BYTES = 96 * 1024
WS_AUTH_TIMEOUT_SECONDS = 5
FORBIDDEN_PLAINTEXT_KEYS = {"plaintext", "plain_text", "text", "body", "message"}
ALLOWED_ENVELOPE_KEYS = {
    "version",
    "algorithm",
    "ephemeral_pub",
    "nonce",
    "ciphertext",
    "sender_pub_x25519",
    "sender_pub_ed25519",
    "hkdf_salt",
    "timestamp",
    "msg_id",
    "to",
    "from",
    "signature",
    # Modern browser envelope field names.
    "ephemeral_public_key",
    "salt",
    "iv",
}

# A process-local map is enough for the single-process deployment used by the
# course project.  A multi-worker deployment would use a broker for routing.
_connections: dict[str, WebSocket] = {}
_connections_lock = asyncio.Lock()


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


LOGIN_WINDOW_SECONDS = _bounded_int("LOGIN_RATE_WINDOW_SECONDS", 300, 30, 3600)
LOGIN_MAX_ATTEMPTS = _bounded_int("LOGIN_RATE_MAX_ATTEMPTS", 8, 2, 100)
_login_attempts: dict[str, deque[float]] = {}
_login_attempts_lock = threading.Lock()


def _login_key(request: Request, username: str) -> str:
    address = request.client.host if request.client else "unknown"
    # Case-folding prevents bypassing the per-user bucket with case variants.
    return f"{address}|{username.casefold()}"


def _login_allowed(key: str) -> tuple[bool, int]:
    now = time.monotonic()
    with _login_attempts_lock:
        attempts = _login_attempts.setdefault(key, deque())
        while attempts and now - attempts[0] >= LOGIN_WINDOW_SECONDS:
            attempts.popleft()
        if len(attempts) >= LOGIN_MAX_ATTEMPTS:
            retry_after = max(1, int(LOGIN_WINDOW_SECONDS - (now - attempts[0])))
            return False, retry_after
    return True, 0


def _record_login_failure(key: str) -> None:
    now = time.monotonic()
    with _login_attempts_lock:
        attempts = _login_attempts.setdefault(key, deque())
        while attempts and now - attempts[0] >= LOGIN_WINDOW_SECONDS:
            attempts.popleft()
        attempts.append(now)


def _clear_login_failures(key: str) -> None:
    with _login_attempts_lock:
        _login_attempts.pop(key, None)


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=12, max_length=256)
    # Modern browser names. Legacy aliases remain accepted for migration.
    exchange_public_key: str | None = Field(default=None, min_length=16, max_length=200)
    signing_public_key: str | None = Field(default=None, min_length=16, max_length=200)
    x25519_pub: str | None = Field(default=None, min_length=16, max_length=200)
    ed25519_pub: str | None = Field(default=None, min_length=16, max_length=200)


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)


def _validate_username(username: str) -> str:
    normalized = username.strip()
    if not USERNAME_RE.fullmatch(normalized):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="username must contain 3-64 letters, numbers, '.', '_' or '-'",
        )
    return normalized


def _validate_public_key(value: str, name: str) -> str:
    """Validate a raw 32-byte public key encoded as base64/base64url."""

    try:
        if not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", value):
            raise ValueError("invalid base64")
        raw = value.encode("ascii")
        # Browser clients commonly omit base64 padding and use the URL-safe
        # alphabet; accepting both forms does not weaken key validation.
        padding = b"=" * (-len(raw) % 4)
        decoded = base64.urlsafe_b64decode(raw + padding)
    except (ValueError, UnicodeEncodeError, binascii.Error):
        raise HTTPException(status_code=422, detail=f"invalid {name} public key") from None
    if len(decoded) != 32:
        raise HTTPException(status_code=422, detail=f"invalid {name} public key")
    return value


def _public_user(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "username": user["username"],
        "exchange_public_key": user["x25519_pub"],
        "signing_public_key": user["ed25519_pub"],
        "ed25519_pub": user["ed25519_pub"],
        "x25519_pub": user["x25519_pub"],
        "created_at": user.get("created_at"),
    }


def _auth_response(user: dict[str, Any]) -> dict[str, Any]:
    public = _public_user(user)
    return {
        "token": auth.create_token(user["username"]),
        "token_type": "bearer",
        "expires_in": auth.TOKEN_TTL_SECONDS,
        **public,
        "user": public,
    }


def _token_from_request(request: Request) -> str | None:
    return auth.token_from_authorization(request.headers.get("authorization"))


def current_user(request: Request) -> dict[str, Any]:
    token = _token_from_request(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        claims = auth.verify_token(token)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or expired session",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    user = db.get_user(claims["sub"])
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or expired session",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def _safe_metadata(**values: Any) -> dict[str, Any]:
    """Keep audit metadata scalar and free of envelope content."""

    return {key: value for key, value in values.items() if isinstance(value, (str, int, bool))}


async def _send_error(websocket: WebSocket, message: str, code: int = 1008) -> None:
    try:
        await websocket.send_json({"type": "error", "error": message})
    except Exception:
        pass


async def _connection_for(username: str) -> WebSocket | None:
    async with _connections_lock:
        return _connections.get(username)


async def _remove_connection(username: str, websocket: WebSocket) -> None:
    async with _connections_lock:
        if _connections.get(username) is websocket:
            _connections.pop(username, None)


async def _deliver(record: dict[str, Any]) -> bool:
    """Try to deliver a queued record and mark it only after send succeeds."""

    websocket = await _connection_for(record["recipient"])
    if websocket is None:
        return False
    payload = {
        "type": "message",
        # Both names are emitted while clients migrate between protocol
        # revisions.  They identify the queue record, not plaintext.
        "id": record["msg_id"],
        "message_id": record["msg_id"],
        "sender": record["sender"],
        "from": record["sender"],
        "to": record["recipient"],
        "envelope": record["envelope"],
    }
    try:
        await websocket.send_json(payload)
    except Exception:
        await _remove_connection(record["recipient"], websocket)
        return False
    # Sending over a socket is not an acknowledgement.  Leave this row
    # pending until the recipient explicitly sends ack so reconnects provide
    # at-least-once delivery.
    return True


async def _notify_sender(sender: str, message_id: str, delivery_status: str) -> None:
    websocket = await _connection_for(sender)
    if websocket is None:
        return
    try:
        await websocket.send_json(
            {
                "type": "ack",
                "message_id": message_id,
                "status": delivery_status,
            }
        )
    except Exception:
        await _remove_connection(sender, websocket)


def _check_envelope(sender: str, recipient: str, envelope: Any) -> tuple[str, dict[str, Any]]:
    if not isinstance(recipient, str) or not USERNAME_RE.fullmatch(recipient):
        raise ValueError("invalid recipient")
    if not isinstance(envelope, dict):
        raise ValueError("envelope must be an object")
    try:
        encoded = json.dumps(envelope, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, UnicodeEncodeError):
        raise ValueError("envelope is not valid JSON") from None
    if len(encoded) > MAX_ENVELOPE_BYTES:
        raise ValueError("envelope too large")
    if envelope.get("from") != sender:
        raise ValueError("envelope sender does not match session")
    if envelope.get("to") != recipient:
        raise ValueError("envelope recipient does not match recipient")
    # Requiring ciphertext makes accidental plaintext storage fail closed.  We
    # do not inspect or decrypt its contents.
    ciphertext = envelope.get("ciphertext")
    if not isinstance(ciphertext, str) or not ciphertext:
        raise ValueError("encrypted ciphertext is required")
    if any(key in envelope for key in FORBIDDEN_PLAINTEXT_KEYS) or not set(envelope).issubset(
        ALLOWED_ENVELOPE_KEYS
    ):
        raise ValueError("plaintext fields are not accepted")
    message_id = envelope.get("msg_id")
    if message_id is None:
        message_id = secrets.token_urlsafe(18)
        envelope = dict(envelope)
        envelope["msg_id"] = message_id
    if not isinstance(message_id, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", message_id):
        raise ValueError("invalid message id")
    return message_id, envelope


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.initialize()
    yield
    # WebSockets are closed by their own disconnect paths.  Do not write
    # private data or tokens while shutting down.


app = FastAPI(
    title="CryptoChat secure messaging API",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/api/docs" if os.environ.get("ENABLE_API_DOCS", "1") == "1" else None,
    redoc_url=None,
)


origins = [origin.strip() for origin in os.environ.get("CORS_ORIGINS", "").split(",") if origin.strip()]
if origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )


@app.middleware("http")
async def security_headers(request: Request, call_next):
    try:
        response = await call_next(request)
    except Exception:
        LOGGER.exception("unhandled request error")
        return JSONResponse(status_code=500, content={"detail": "internal server error"})
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'",
    )
    if request.url.path.startswith("/api") or request.url.path == "/ws":
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/register", status_code=201)
def register(payload: RegisterRequest, request: Request) -> dict[str, Any]:
    username = _validate_username(payload.username)
    signing_key = payload.signing_public_key or payload.ed25519_pub
    exchange_key = payload.exchange_public_key or payload.x25519_pub
    if not signing_key or not exchange_key:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="exchange_public_key and signing_public_key are required",
        )
    ed_pub = _validate_public_key(signing_key, "signing")
    x_pub = _validate_public_key(exchange_key, "exchange")
    admin_username = os.environ.get("ADMIN_USERNAME", "").strip()
    created = db.create_user(
        username,
        auth.hash_password(payload.password),
        ed_pub,
        x_pub,
        is_admin=bool(admin_username and username == admin_username),
    )
    if not created:
        raise HTTPException(status_code=409, detail="username already registered")
    db.add_audit(username, "register", username)
    user = db.get_user(username)
    assert user is not None
    return _auth_response(user)


@app.post("/api/login")
def login(payload: LoginRequest, request: Request) -> dict[str, Any]:
    username = payload.username.strip()
    rate_key = _login_key(request, username)
    allowed, retry_after = _login_allowed(rate_key)
    if not allowed:
        db.add_audit(
            username if USERNAME_RE.fullmatch(username) else None,
            "login_rate_limited",
            username or None,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too many login attempts; try again later",
            headers={"Retry-After": str(retry_after)},
        )
    user = db.get_user(username)
    if not user or not auth.verify_password(user["password_hash"], payload.password):
        _record_login_failure(rate_key)
        # The audit record has no password, key, or message content.
        db.add_audit(username if USERNAME_RE.fullmatch(username) else None, "login_failed", username or None)
        raise HTTPException(status_code=401, detail="invalid username or password")
    _clear_login_failures(rate_key)
    upgraded = auth.maybe_rehash(user["password_hash"], payload.password)
    if upgraded:
        with db.connection() as conn:
            conn.execute("UPDATE users SET password_hash = ? WHERE username = ?", (upgraded, username))
    db.add_audit(username, "login", username)
    return _auth_response(user)


@app.get("/api/me")
def me(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    public = _public_user(user)
    # Keep both a convenient top-level shape and the nested shape used by the
    # first web client release.
    return {**public, "user": public, "is_admin": bool(user.get("is_admin"))}


@app.get("/api/users")
def users(_: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    entries = []
    for item in db.list_users():
        item["exchange_public_key"] = item["x25519_pub"]
        item["signing_public_key"] = item["ed25519_pub"]
        item["online"] = item["username"] in _connections
        entries.append(item)
    return {"users": entries}


@app.get("/api/users/{username}/keys")
def user_keys(username: str, _: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    username = _validate_username(username)
    user = db.get_user(username)
    if not user:
        raise HTTPException(status_code=404, detail="user not found")
    return {
        "username": username,
        "exchange_public_key": user["x25519_pub"],
        "signing_public_key": user["ed25519_pub"],
        "ed25519_pub": user["ed25519_pub"],
        "x25519_pub": user["x25519_pub"],
    }


@app.get("/api/audit")
def audit(
    limit: int = Query(default=100, ge=1, le=500),
    user: dict[str, Any] = Depends(current_user),
) -> dict[str, Any]:
    return {"events": db.list_audit(user["username"], bool(user.get("is_admin")), limit)}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    # Tokens in query strings are routinely copied to reverse-proxy access
    # logs, browser history and monitoring systems.  Reject the old form
    # rather than silently accepting a credential in the URL.
    if "token" in websocket.query_params:
        await websocket.close(code=1008, reason="token must be sent in auth frame")
        return
    await websocket.accept()
    try:
        raw_auth = await asyncio.wait_for(
            websocket.receive_text(), timeout=WS_AUTH_TIMEOUT_SECONDS
        )
        if len(raw_auth.encode("utf-8")) > MAX_WEBSOCKET_BYTES:
            raise ValueError("authentication frame too large")
        auth_message = json.loads(raw_auth)
        if (
            not isinstance(auth_message, dict)
            or set(auth_message) != {"type", "token"}
            or auth_message.get("type") != "auth"
            or not isinstance(auth_message.get("token"), str)
        ):
            raise ValueError("invalid authentication frame")
        token = auth_message["token"]
        claims = auth.verify_token(token)
        username = claims["sub"]
        user = db.get_user(username)
        if not user:
            raise ValueError("unknown user")
    except (ValueError, KeyError, TypeError, json.JSONDecodeError, asyncio.TimeoutError):
        await websocket.close(code=1008, reason="invalid or expired session")
        return

    await websocket.send_json({"type": "ready", "username": username})
    old: WebSocket | None = None
    async with _connections_lock:
        old = _connections.get(username)
        _connections[username] = websocket
    if old is not None and old is not websocket:
        try:
            await old.close(code=4001, reason="new session connected")
        except Exception:
            pass

    db.add_audit(username, "websocket_connected", username)
    try:
        # Deliver in insertion order.  If a send fails, leave the message
        # pending so the next connection can retry it.
        for record in db.pending_messages(username):
            if not await _deliver(record):
                break
        while True:
            raw = await websocket.receive_text()
            if len(raw.encode("utf-8")) > MAX_WEBSOCKET_BYTES:
                await _send_error(websocket, "message too large")
                continue
            try:
                obj = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                await _send_error(websocket, "invalid JSON")
                continue
            if not isinstance(obj, dict):
                await _send_error(websocket, "message must be an object")
                continue

            message_type = obj.get("type")
            if message_type == "message":
                recipient = obj.get("recipient")
                try:
                    message_id, envelope = _check_envelope(username, recipient, obj.get("envelope"))
                except ValueError as exc:
                    await _send_error(websocket, str(exc))
                    continue
                if recipient == username:
                    await _send_error(websocket, "cannot send a message to yourself")
                    continue
                if not db.get_user(recipient):
                    await _send_error(websocket, "recipient not found")
                    continue
                record, inserted = db.enqueue_message(message_id, username, recipient, envelope)
                if not inserted:
                    # A repeated msg_id is idempotent and cannot overwrite a
                    # message belonging to a different sender or recipient.
                    if record["sender"] != username or record["recipient"] != recipient:
                        await _send_error(websocket, "message id already belongs to another message")
                        continue
                else:
                    db.add_audit(username, "message_queued", recipient, _safe_metadata(message_id=message_id))
                if record.get("delivered_at"):
                    delivery_status = "delivered"
                else:
                    sent = await _deliver(record)
                    delivery_status = "sent" if sent else "queued"
                await _notify_sender(username, message_id, delivery_status)
            elif message_type == "ack":
                message_id = obj.get("message_id", obj.get("msg_id"))
                if not isinstance(message_id, str) or len(message_id) > 128:
                    await _send_error(websocket, "invalid message id")
                    continue
                record = db.get_message(message_id)
                if not record or record["recipient"] != username:
                    await _send_error(websocket, "message not found")
                    continue
                db.mark_delivered(message_id, username)
                db.add_audit(username, "message_acknowledged", record["sender"], _safe_metadata(message_id=message_id))
                await _notify_sender(record["sender"], message_id, "delivered")
                await websocket.send_json({"type": "ack", "message_id": message_id, "status": "acknowledged"})
            else:
                await _send_error(websocket, "unknown message type")
    except WebSocketDisconnect:
        pass
    except Exception:
        LOGGER.exception("websocket failure for user %s", username)
    finally:
        await _remove_connection(username, websocket)
        db.add_audit(username, "websocket_disconnected", username)


frontend_path = Path(__file__).resolve().parent.parent / "frontend"
if frontend_path.is_dir():
    app.mount("/", StaticFiles(directory=str(frontend_path), html=True), name="frontend")
