"""Security-focused API tests for the web backend."""

from __future__ import annotations

import base64
from starlette.websockets import WebSocketDisconnect

import pytest
from fastapi.testclient import TestClient

from app import main as main_module
from app import auth
from app.main import app


def key(value: int) -> str:
    return base64.b64encode(bytes([value]) * 32).decode("ascii")


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("MESSAGING_DATABASE", str(tmp_path / "messaging.sqlite3"))
    monkeypatch.setenv("SESSION_SECRET", "test-only-secret-that-is-not-used-in-production")
    main_module._login_attempts.clear()
    with TestClient(app) as test_client:
        yield test_client
    main_module._login_attempts.clear()


def register(client: TestClient, username: str, number: int) -> dict:
    response = client.post(
        "/api/register",
        json={
            "username": username,
            "password": f"{username}-secure-password-12",
            "signing_public_key": key(number),
            "exchange_public_key": key(number + 1),
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def authenticate_socket(websocket, token: str, username: str) -> None:
    websocket.send_json({"type": "auth", "token": token})
    assert websocket.receive_json() == {"type": "ready", "username": username}


def test_placeholder_session_secret_is_rejected(monkeypatch):
    monkeypatch.setenv("SESSION_SECRET", "replace-with-a-random-32-byte-secret")
    with pytest.raises(RuntimeError, match="SESSION_SECRET"):
        auth.create_token("alice")


def test_register_login_and_protected_endpoints(client):
    created = register(client, "alice", 1)
    token = created["token"]

    me = client.get("/api/me", headers=auth_header(token))
    assert me.status_code == 200
    assert me.json()["user"]["username"] == "alice"
    assert me.json()["exchange_public_key"] == key(2)
    assert me.json()["signing_public_key"] == key(1)

    login = client.post(
        "/api/login",
        json={"username": "alice", "password": "alice-secure-password-12"},
    )
    assert login.status_code == 200
    assert login.json()["token"]

    assert client.get("/api/me").status_code == 401
    assert client.post(
        "/api/login", json={"username": "alice", "password": "wrong-password"}
    ).status_code == 401


def test_login_rate_limit_returns_retry_after(client, monkeypatch):
    register(client, "alice", 21)
    monkeypatch.setattr(main_module, "LOGIN_MAX_ATTEMPTS", 2)
    monkeypatch.setattr(main_module, "LOGIN_WINDOW_SECONDS", 60)

    for _ in range(2):
        response = client.post(
            "/api/login", json={"username": "alice", "password": "wrong-password"}
        )
        assert response.status_code == 401
    limited = client.post(
        "/api/login", json={"username": "alice", "password": "wrong-password"}
    )
    assert limited.status_code == 429
    assert int(limited.headers["retry-after"]) >= 1


def test_websocket_rejects_invalid_auth_frame(client):
    with client.websocket_connect("/ws") as websocket:
        websocket.send_json({"type": "auth", "token": "not-a-valid-token"})
        with pytest.raises(WebSocketDisconnect) as error:
            websocket.receive_json()
        assert error.value.code == 1008


def test_envelope_sender_cannot_be_spoofed(client):
    alice = register(client, "alice", 1)
    register(client, "bob", 3)

    with client.websocket_connect("/ws") as websocket:
        authenticate_socket(websocket, alice["token"], "alice")
        websocket.send_json(
            {
                "type": "message",
                "recipient": "bob",
                "envelope": {
                    "version": 1,
                    "algorithm": "X25519-HKDF-SHA256-AES-256-GCM+Ed25519",
                    "from": "mallory",
                    "to": "bob",
                    "msg_id": "spoofed-1",
                    "timestamp": 1,
                    "ephemeral_public_key": key(9),
                    "salt": key(10),
                    "iv": key(11)[:16],
                    "ciphertext": "AA==",
                    "signature": key(12),
                },
            }
        )
        error = websocket.receive_json()
        assert error["type"] == "error"
        assert "sender" in error["error"]


def test_offline_envelope_is_queued_and_delivered(client):
    alice = register(client, "alice", 1)
    bob = register(client, "bob", 3)

    with client.websocket_connect("/ws") as websocket:
        authenticate_socket(websocket, alice["token"], "alice")
        websocket.send_json(
            {
                "type": "message",
                "recipient": "bob",
                "envelope": {
                    "version": 1,
                    "algorithm": "X25519-HKDF-SHA256-AES-256-GCM+Ed25519",
                    "from": "alice",
                    "to": "bob",
                    "msg_id": "offline-1",
                    "timestamp": 1,
                    "ephemeral_public_key": key(9),
                    "salt": key(10),
                    "iv": key(11)[:16],
                    "ciphertext": "AA==",
                    "signature": key(12),
                },
            }
        )
        ack = websocket.receive_json()
        assert ack == {"type": "ack", "message_id": "offline-1", "status": "queued"}

    with client.websocket_connect("/ws") as websocket:
        authenticate_socket(websocket, bob["token"], "bob")
        message = websocket.receive_json()
        assert message["type"] == "message"
        assert message["id"] == "offline-1"
        assert message["message_id"] == "offline-1"
        assert message["from"] == "alice"
        assert message["sender"] == "alice"
        assert message["envelope"]["ciphertext"] == "AA=="
        websocket.send_json({"type": "ack", "message_id": "offline-1"})
        assert websocket.receive_json()["status"] == "acknowledged"

    events = client.get("/api/audit", headers=auth_header(bob["token"])).json()["events"]
    assert any(event["event"] == "message_acknowledged" for event in events)


def test_modern_envelope_is_sent_then_delivered_only_after_ack(client):
    alice = register(client, "alice", 1)
    bob = register(client, "bob", 3)

    with client.websocket_connect("/ws") as bob_socket:
        authenticate_socket(bob_socket, bob["token"], "bob")
        with client.websocket_connect("/ws") as alice_socket:
            authenticate_socket(alice_socket, alice["token"], "alice")
            envelope = {
                "version": 1,
                "algorithm": "X25519-HKDF-SHA256-AES-256-GCM+Ed25519",
                "from": "alice",
                "to": "bob",
                "timestamp": 1700000000000,
                "msg_id": "modern-1",
                "ephemeral_public_key": key(5),
                "salt": key(6),
                "iv": key(7)[:16],
                "ciphertext": "AA==",
                "signature": key(8),
            }
            alice_socket.send_json({"type": "message", "recipient": "bob", "envelope": envelope})
            assert alice_socket.receive_json() == {
                "type": "ack",
                "message_id": "modern-1",
                "status": "sent",
            }
            delivered = bob_socket.receive_json()
            assert delivered["id"] == delivered["message_id"] == "modern-1"
            assert delivered["sender"] == delivered["from"] == "alice"

            from app import db

            assert db.get_message("modern-1")["delivered_at"] is None
            bob_socket.send_json({"type": "ack", "message_id": "modern-1"})
            assert bob_socket.receive_json()["status"] == "acknowledged"
            assert alice_socket.receive_json() == {
                "type": "ack",
                "message_id": "modern-1",
                "status": "delivered",
            }
            assert db.get_message("modern-1")["delivered_at"] is not None
