import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import socket, threading, json, os, base64, time
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import uuid, datetime, stat, json as _json


SERVER_IP = "127.0.0.1"
SERVER_PORT = 5555

# ---------- crypto helpers ----------
def b64(x): return base64.b64encode(x).decode()
def ub64(s): return base64.b64decode(s)

def gen_keys():
    xpriv = x25519.X25519PrivateKey.generate()
    epriv = ed25519.Ed25519PrivateKey.generate()
    return xpriv, epriv

def save_keys(username, xpriv, epriv):
    os.makedirs(".keys", exist_ok=True)
    xp = f".keys/{username}.xpriv"
    ep = f".keys/{username}.epriv"
    with open(xp,"wb") as f:
        f.write(xpriv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()))
    with open(ep,"wb") as f:
        f.write(epriv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()))
    set_secure_perms(xp)
    set_secure_perms(ep)

def load_keys(username):
    try:
        with open(f".keys/{username}.xpriv","rb") as f:
            xpriv = x25519.X25519PrivateKey.from_private_bytes(f.read())
        with open(f".keys/{username}.epriv","rb") as f:
            epriv = ed25519.Ed25519PrivateKey.from_private_bytes(f.read())
        return xpriv, epriv
    except Exception:
        return None

def pub_bytes(privkey):
    return privkey.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                             format=serialization.PublicFormat.Raw)

def derive_shared_key(ephemeral_pub_bytes, receiver_priv):
    eph_pub = x25519.X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)
    shared = receiver_priv.exchange(eph_pub)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"messaging-v1")
    return hkdf.derive(shared)

def encrypt_for(message_bytes, receiver_pub_x_bytes, sender_ed_priv, sender_x25519_pub_bytes, sender_name, to_name):
    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub_bytes = eph_priv.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                                       format=serialization.PublicFormat.Raw)
    receiver_pub = x25519.X25519PublicKey.from_public_bytes(receiver_pub_x_bytes)
    shared = eph_priv.exchange(receiver_pub)

    hkdf_salt = os.urandom(16)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=hkdf_salt, info=b"messaging-v1")
    key = hkdf.derive(shared)

    ts = datetime.datetime.utcnow().isoformat(timespec="seconds")+"Z"
    msg_id = str(uuid.uuid4())

    aad = f"1|{sender_name}|{to_name}|{ts}|{msg_id}".encode()
    aead = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ct = aead.encrypt(nonce, message_bytes, aad)

    env = {
        "version": "1",
        "ephemeral_pub": b64(eph_pub_bytes),
        "nonce": b64(nonce),
        "ciphertext": b64(ct),
        "sender_pub_x25519": b64(sender_x25519_pub_bytes),
        "sender_pub_ed25519": b64(sender_ed_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)),
        "hkdf_salt": b64(hkdf_salt),
        "timestamp": ts,
        "msg_id": msg_id,
        "to": to_name,
        "from": sender_name
    }

    to_sign = (env["version"]+"|"+env["ephemeral_pub"]+"|"+env["nonce"]+"|"+
               env["ciphertext"]+"|"+env["sender_pub_x25519"]+"|"+env["timestamp"]+"|"+env["msg_id"]+"|"+env["to"]+"|"+env["from"]).encode()
    sig = sender_ed_priv.sign(to_sign)
    env["signature"] = b64(sig)
    return env

def fingerprint(pub_bytes):
    d = hashes.Hash(hashes.SHA256())
    d.update(pub_bytes)
    return d.finalize().hex()

PIN_FILE = ".keys/pinned.json"
REPLAY_WINDOW = 1000  # máx. ids recordados por sesión

def set_secure_perms(path):
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

def load_pins():
    try:
        with open(PIN_FILE,"r") as f:
            return _json.load(f)
    except Exception:
        return {}

def save_pins(pins):
    os.makedirs(".keys", exist_ok=True)
    with open(PIN_FILE,"w") as f:
        _json.dump(pins, f, indent=2)
    set_secure_perms(PIN_FILE)


# ---------- client GUI ----------
class ChatClient(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Crypto Chat")
        self.geometry("820x520")
        self.sock = None
        self.reader = None
        self.username = None
        self.xpriv = None
        self.epriv = None
        self.pubcache = {}
        self.seen_ids = set()
        self.pins = load_pins()

        top = tk.Frame(self)
        top.pack(fill="x", padx=6, pady=6)
        tk.Label(top, text="Usuario:").pack(side="left")
        self.entry_user = tk.Entry(top, width=18)
        self.entry_user.pack(side="left", padx=4)
        tk.Button(top, text="Conectar", command=self.connect_server).pack(side="left", padx=4)
        self.lbl_status = tk.Label(top, text="Desconectado")
        self.lbl_status.pack(side="left", padx=8)

        body = tk.PanedWindow(self, sashrelief="raised")
        body.pack(fill="both", expand=True)

        left = tk.Frame(body); right = tk.Frame(body)
        body.add(left, width=250); body.add(right)

        # left
        tk.Label(left, text="Usuarios en línea").pack(anchor="w", padx=6, pady=6)
        self.users = tk.Listbox(left); self.users.pack(fill="both", expand=True, padx=6, pady=6)
        tk.Button(left, text="Actualizar", command=self.request_users).pack(padx=6, pady=4)
        self.lbl_fp = tk.Label(left, text="Huella propia: -", wraplength=230, justify="left")
        self.lbl_fp.pack(padx=6, pady=6, anchor="w")

        # right
        self.chat = tk.Text(right, state="disabled", wrap="word")
        self.chat.pack(fill="both", expand=True, padx=6, pady=6)
        bottom = tk.Frame(right); bottom.pack(fill="x", padx=6, pady=6)
        tk.Label(bottom, text="Para:").pack(side="left")
        self.to_entry = tk.Entry(bottom, width=18); self.to_entry.pack(side="left", padx=4)
        self.msg_entry = tk.Entry(bottom); self.msg_entry.pack(side="left", fill="x", expand=True, padx=4)
        tk.Button(bottom, text="Enviar", command=self.send_message).pack(side="left", padx=4)

        self.users.bind("<<ListboxSelect>>", self.on_pick_user)

    def decrypt_envelope(self, envelope, my_xpriv):
        # 1) pinning (TOFU) + estructura con verified
        sender = envelope.get("from","")
        if sender:
            spinned = self.pins.get(sender)
            if spinned:
                # si ya está pinneado, no permitimos cambios de llave
                if spinned.get("x25519_pub") != envelope.get("sender_pub_x25519") or \
                   spinned.get("ed25519_pub") != envelope.get("sender_pub_ed25519"):
                    raise ValueError("Cambio de llaves públicas detectado para "+sender+" (posible MITM)")
            else:
                # primera vez: pin (aún no verificado OOB)
                self.pins[sender] = {
                    "x25519_pub": envelope.get("sender_pub_x25519",""),
                    "ed25519_pub": envelope.get("sender_pub_ed25519",""),
                    "verified": False
                }
                save_pins(self.pins)

        # 2) anti-replay
        mid = envelope.get("msg_id","")
        if mid in self.seen_ids:
            raise ValueError("Mensaje repetido (replay)")
        if len(self.seen_ids) > REPLAY_WINDOW:
            # recorta cache
            self.seen_ids = set(list(self.seen_ids)[-REPLAY_WINDOW:])
        self.seen_ids.add(mid)

        # 3) verificar firma
        to_sign = (envelope["version"]+"|"+envelope["ephemeral_pub"]+"|"+envelope["nonce"]+"|"+
                envelope["ciphertext"]+"|"+envelope.get("sender_pub_x25519","")+"|"+
                envelope.get("timestamp","")+"|"+envelope.get("msg_id","")+"|"+
                envelope.get("to","")+"|"+envelope.get("from","")).encode()
        spub = ed25519.Ed25519PublicKey.from_public_bytes(ub64(envelope["sender_pub_ed25519"]))
        spub.verify(ub64(envelope["signature"]), to_sign)

        # 4) derivar clave con SALT y desencriptar con AAD
        hkdf_salt = ub64(envelope["hkdf_salt"])
        eph_pub = x25519.X25519PublicKey.from_public_bytes(ub64(envelope["ephemeral_pub"]))
        shared = my_xpriv.exchange(eph_pub)
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=hkdf_salt, info=b"messaging-v1")
        key = hkdf.derive(shared)
        aead = ChaCha20Poly1305(key)
        aad = f'{envelope["version"]}|{envelope.get("from","")}|{envelope.get("to","")}|{envelope.get("timestamp","")}|{envelope.get("msg_id","")}'.encode()
        pt = aead.decrypt(ub64(envelope["nonce"]), ub64(envelope["ciphertext"]), aad)
        return pt

    def log(self, text):
        self.chat.configure(state="normal")
        self.chat.insert("end", text+"\n")
        self.chat.configure(state="disabled")
        self.chat.see("end")

    # networking
    def connect_server(self):
        if self.sock:
            return
        u = self.entry_user.get().strip()
        if not u:
            messagebox.showerror("Error","Ingresa un nombre de usuario")
            return
        self.username = u
        keys = load_keys(u)
        if keys:
            self.xpriv, self.epriv = keys
        else:
            self.xpriv, self.epriv = gen_keys()
            save_keys(u, self.xpriv, self.epriv)
        my_xpub = self.xpriv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        my_epub = self.epriv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        self.lbl_fp.config(text=f"Huella X25519: {fingerprint(my_xpub)[:16]}…\nHuella Ed25519: {fingerprint(my_epub)[:16]}…")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_IP, SERVER_PORT))
        self.sock = s
        self.reader = s.makefile('rb')
        hello = {"type":"hello","username":u,"ed25519_pub": b64(my_epub), "x25519_pub": b64(my_xpub)}
        self._send_json(hello)
        threading.Thread(target=self.recv_loop, daemon=True).start()
        self.lbl_status.config(text="Conectado")
        self.request_users()

    def _send_json(self, obj):
        if not self.sock: return
        self.sock.sendall((json.dumps(obj)+"\n").encode())

    def request_users(self):
        self._send_json({"type":"get_users"})

    def on_pick_user(self, evt):
        sel = self.users.curselection()
        if not sel: return
        name = self.users.get(sel[0])
        self.to_entry.delete(0, "end")
        self.to_entry.insert(0, name)

    def ensure_pub_for(self, username):
        if username in self.pubcache:
            return self.pubcache[username]
        self._send_json({"type":"get_pubkey","username": username})
        # espera breve por la respuesta
        for _ in range(20):
            if username in self.pubcache: return self.pubcache[username]
            time.sleep(0.05)
        raise RuntimeError("No se pudo obtener la llave pública de "+username)

    def ensure_verified_contact(self, username, rec):
        """
        Se asegura de que la llave pública de `username`:
        - esté pinneada
        - no haya cambiado
        - esté marcada como verificada fuera de banda

        Si el usuario no confirma, NO se envía el mensaje.
        Devuelve True si se puede seguir, False si hay que abortar el envío.
        """
        x_pub_b64 = rec.get("x25519_pub")
        e_pub_b64 = rec.get("ed25519_pub")
        if x_pub_b64 is None or e_pub_b64 is None:
            messagebox.showerror("Error", f"No se encontraron llaves públicas para {username}.")
            return False

        info = self.pins.get(username)

        # 1) si no está pinneado todavía, lo pinneamos ahora con verified = False
        if info is None:
            info = {
                "x25519_pub": x_pub_b64,
                "ed25519_pub": e_pub_b64,
                "verified": False
            }
            self.pins[username] = info
            save_pins(self.pins)
        else:
            # 2) si está pinneado pero el servidor manda otra llave → MITM
            if info.get("x25519_pub") != x_pub_b64 or info.get("ed25519_pub") != e_pub_b64:
                messagebox.showerror(
                    "Alerta de seguridad",
                    f"La llave pública de {username} ha cambiado.\n"
                    "Por seguridad se bloquea el envío (posible ataque MITM)."
                )
                return False

        # 3) si ya está verificado → todo bien, podemos continuar
        if info.get("verified"):
            return True

        # 4) si NO está verificado, pedimos confirmación al usuario
        try:
            xfp = fingerprint(ub64(x_pub_b64))[:16]
            efp = fingerprint(ub64(e_pub_b64))[:16]
        except Exception:
            xfp = "<no disponible>"
            efp = "<no disponible>"

        msg = (
            f"Huellas de {username}:\n\n"
            f"X25519: {xfp}\n"
            f"Ed25519: {efp}\n\n"
            "Confirma SOLO si ya verificaste estas huellas con esta persona "
            "por un canal externo (llamada, WhatsApp, en persona, etc.).\n\n"
            "¿Coinciden las huellas?"
        )

        ok = messagebox.askyesno("Verificar huellas (OOB)", msg)
        if not ok:
            # el usuario no quiere confirmar → no enviamos
            self.log(f"[info] No se verificaron las huellas de {username}. Envío cancelado.")
            return False

        # el usuario confirmó → marcamos como verificado
        info["verified"] = True
        self.pins[username] = info
        save_pins(self.pins)
        self.log(f"[seguridad] Huellas de {username} marcadas como verificadas.")
        return True

    def send_message(self):
        to = self.to_entry.get().strip()
        text_str = self.msg_entry.get()
        text = text_str.encode()
        if not to or not text:
            return
        try:
            rec = self.ensure_pub_for(to)

            # NUEVO: asegurarnos de que la llave pública del destinatario
            # está pinneada y verificada fuera de banda
            if not self.ensure_verified_contact(to, rec):
                return  # cancelar envío

            env = encrypt_for(text, ub64(rec["x25519_pub"]), self.epriv, pub_bytes(self.xpriv), self.username, to)
            self._send_json({"type":"send","to": to, "envelope": env})
            self.log(f"[Yo → {to}] {text_str}")
            self.msg_entry.delete(0, "end")
        except Exception as e:
            messagebox.showerror("Error al cifrar/enviar", str(e))

    def recv_loop(self):
        try:
            while True:
                line = self.reader.readline()
                if not line: break
                obj = json.loads(line.decode())
                t = obj.get("type")
                if t == "hello_ok":
                    self.log(f"Conectado como {obj['username']}")
                elif t == "users":
                    self.users.delete(0,"end")
                    for u in obj["users"]:
                        if u != self.username:
                            self.users.insert("end", u)
                elif t == "pubkey":
                    self.pubcache[obj["username"]] = {"x25519_pub": obj["x25519_pub"], "ed25519_pub": obj["ed25519_pub"]}
                    # Mostrar huellas cuando se obtiene por primera vez (solo info)
                    if obj["username"] not in self.pins:
                        xfp = fingerprint(ub64(obj["x25519_pub"]))[:16]
                        efp = fingerprint(ub64(obj["ed25519_pub"]))[:16]
                        self.log(f"[info] Huellas de {obj['username']} → X25519:{xfp}…  Ed25519:{efp}… (verifíquenlas fuera de banda)")
                elif t == "msg":
                    try:
                        pt = self.decrypt_envelope(obj["envelope"], self.xpriv)
                        self.log(f"[{obj['from']} → Yo] {pt.decode()}")
                    except Exception as e:
                        self.log(f"[!] Error al descifrar de {obj.get('from')}: {e}")
                elif t == "error":
                    self.log("[server] error: "+obj.get("error",""))
        except Exception as e:
            self.log(f"[conn] cerrada: {e}")
        finally:
            self.sock = None
            self.lbl_status.config(text="Desconectado")

if __name__ == "__main__":
    ChatClient().mainloop()
