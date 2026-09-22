import socket
import threading
import json
import datetime

HOST = '127.0.0.1'
PORT = 5555

clients = {}          # sock -> {"username": str}
sockets_by_user = {}  # username -> sock
pubkeys = {}          # username -> {"ed25519_pub": b64, "x25519_pub": b64}


# ---------- logging helper ----------
def log(msg):
    """Imprime mensajes de log con timestamp."""
    now = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{now}] {msg}")


def send_json(sock, obj):
    try:
        data = (json.dumps(obj) + '\n').encode('utf-8')
        sock.sendall(data)

        # logging de lo que enviamos
        t = obj.get("type")
        if t == "users":
            log(f"[SEND] -> {sock.fileno()} type=users users={obj.get('users')}")
        elif t == "hello_ok":
            log(f"[SEND] -> {sock.fileno()} type=hello_ok username={obj.get('username')}")
        elif t == "pubkey":
            log(f"[SEND] -> {sock.fileno()} type=pubkey username={obj.get('username')}")
        elif t == "msg":
            env = obj.get("envelope", {})
            log(f"[SEND] -> {sock.fileno()} type=msg from={obj.get('from')} msg_id={env.get('msg_id')}")
        elif t == "error":
            log(f"[SEND] -> {sock.fileno()} type=error error={obj.get('error')}")
        else:
            log(f"[SEND] -> {sock.fileno()} type={t}")
    except Exception as e:
        log(f"[ERROR] al enviar a {sock.fileno()}: {e}")


def broadcast_users():
    users = sorted(list(sockets_by_user.keys()))
    msg = {"type": "users", "users": users}
    log(f"[USERS] broadcast lista usuarios: {users}")
    for s in list(clients.keys()):
        send_json(s, msg)


def handle_client(sock, addr):
    log(f"[CONN] Nuevo cliente desde {addr}, fd={sock.fileno()}")
    buf = b""
    f = sock.makefile('rb')
    try:
        while True:
            line = f.readline()
            if not line:
                log(f"[CONN] fd={sock.fileno()} cerró la conexión (EOF)")
                break
            try:
                obj = json.loads(line.decode('utf-8'))
            except Exception as e:
                log(f"[ERROR] JSON inválido desde fd={sock.fileno()}: {e}")
                continue

            t = obj.get("type")
            log(f"[RECV] fd={sock.fileno()} type={t} data={ {k: obj[k] for k in obj if k != 'envelope'} }")

            if t == "hello":
                username = obj.get("username")
                ed = obj.get("ed25519_pub")
                xk = obj.get("x25519_pub")

                if not username or not ed or not xk:
                    log(f"[HELLO] inválido desde fd={sock.fileno()}")
                    send_json(sock, {"type":"error","error":"invalid hello"})
                    continue

                # desconectar sesión previa si existe
                if username in sockets_by_user:
                    old_sock = sockets_by_user[username]
                    log(f"[HELLO] {username} ya conectado en fd={old_sock.fileno()}, cerrando sesión previa")
                    try:
                        old_sock.close()
                    except Exception:
                        pass

                clients[sock] = {"username": username}
                sockets_by_user[username] = sock
                pubkeys[username] = {"ed25519_pub": ed, "x25519_pub": xk}

                log(f"[HELLO] {username} registrado, claves publicadas")
                send_json(sock, {"type":"hello_ok","username": username})
                broadcast_users()

            elif t == "get_users":
                log(f"[GET_USERS] fd={sock.fileno()} pidió lista de usuarios")
                send_json(sock, {"type":"users","users": sorted(list(sockets_by_user.keys()))})

            elif t == "get_pubkey":
                u = obj.get("username")
                data = pubkeys.get(u)
                if data:
                    log(f"[GET_PUBKEY] fd={sock.fileno()} pidió pubkeys de {u}")
                    send_json(sock, {"type":"pubkey","username":u, **data})
                else:
                    log(f"[GET_PUBKEY] usuario {u} no encontrado")
                    send_json(sock, {"type":"error","error":"user not found"})

            elif t == "send":
                to = obj.get("to")
                envelope = obj.get("envelope")
                sender = clients.get(sock,{}).get("username")
                if not to or not envelope or not sender:
                    log(f"[SEND] mensaje inválido desde fd={sock.fileno()}")
                    send_json(sock, {"type":"error","error":"invalid send"})
                    continue

                rsock = sockets_by_user.get(to)
                if not rsock:
                    log(f"[SEND] destinatario {to} offline (desde {sender})")
                    send_json(sock, {"type":"error","error":"recipient offline"})
                    continue

                msg_id = envelope.get("msg_id")
                log(f"[SEND] reenviando msg_id={msg_id} de {sender} a {to} (fd={rsock.fileno()})")
                send_json(rsock, {"type":"msg","from": sender, "envelope": envelope})

            else:
                log(f"[WARN] tipo desconocido desde fd={sock.fileno()}: {t}")
                send_json(sock, {"type":"error","error":"unknown type"})

    except Exception as e:
        log(f"[ERROR] excepción en handle_client fd={sock.fileno()}: {e}")
    finally:
        info = clients.pop(sock, None)
        if info:
            u = info.get("username")
            if sockets_by_user.get(u) is sock:
                sockets_by_user.pop(u, None)
                log(f"[DISCONN] usuario {u} desconectado, fd={sock.fileno()}")
        try:
            sock.close()
        except Exception:
            pass
        broadcast_users()


def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen()
        log(f"[SERVER] listening on {HOST}:{PORT}")
        while True:
            s, addr = srv.accept()
            threading.Thread(target=handle_client, args=(s, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()
