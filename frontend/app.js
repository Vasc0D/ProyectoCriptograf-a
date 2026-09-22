/* global crypto, indexedDB, WebSocket */

"use strict";

const DB_NAME = "clave-e2ee-v1";
const DB_VERSION = 1;
const MAX_MESSAGE_AGE_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;
const ALGORITHM_LABEL = "X25519-HKDF-SHA256-AES-256-GCM-Ed25519";

const state = {
  cryptoReady: false,
  dbReady: false,
  token: null,
  username: null,
  identity: null,
  users: [],
  peers: new Map(),
  activePeer: null,
  messages: new Map(),
  replay: new Set(),
  ownMessageIds: new Set(),
  socket: null,
  socketReady: false,
  socketQueue: [],
  socketGeneration: 0,
  reconnectTimer: null,
};

const dom = {};
let dbPromise;

document.addEventListener("DOMContentLoaded", init);

async function init() {
  cacheDom();
  bindEvents();
  setAuthTab("login");
  dbPromise = openDatabase();
  try {
    await dbPromise;
    state.dbReady = true;
  } catch (error) {
    setGlobalAlert("No se pudo abrir el almacén local de claves. Usa un perfil normal del navegador y vuelve a intentarlo.", "danger");
  }
  await detectCryptoSupport();
}

function cacheDom() {
  const ids = [
    "security-warning", "security-warning-text", "global-alert", "auth-view", "app-view",
    "login-tab", "register-tab", "login-panel", "register-panel", "login-help",
    "current-username", "connection-status", "logout-button", "refresh-users",
    "contact-search", "contacts-list", "no-chat-state", "active-chat", "chat-title",
    "chat-avatar", "chat-key-status", "show-fingerprint", "fingerprint-panel",
    "close-fingerprint", "fingerprint-description", "fingerprint-value", "fingerprint-action",
    "message-list", "chat-alert", "message-form", "message-input", "send-button",
  ];
  for (const id of ids) dom[id] = document.getElementById(id);
}

function bindEvents() {
  dom["login-tab"].addEventListener("click", () => setAuthTab("login"));
  dom["register-tab"].addEventListener("click", () => setAuthTab("register"));
  dom["login-panel"].addEventListener("submit", handleLogin);
  dom["register-panel"].addEventListener("submit", handleRegister);
  dom["logout-button"].addEventListener("click", logout);
  dom["refresh-users"].addEventListener("click", () => refreshUsers(true));
  dom["contact-search"].addEventListener("input", renderContacts);
  dom["show-fingerprint"].addEventListener("click", () => {
    dom["fingerprint-panel"].hidden = false;
  });
  dom["close-fingerprint"].addEventListener("click", () => {
    dom["fingerprint-panel"].hidden = true;
  });
  dom["message-form"].addEventListener("submit", handleSendMessage);
  dom["message-input"].addEventListener("input", resizeComposer);
  dom["message-input"].addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      dom["message-form"].requestSubmit();
    }
  });
}

function setAuthTab(tab) {
  const login = tab === "login";
  dom["login-tab"].classList.toggle("is-active", login);
  dom["register-tab"].classList.toggle("is-active", !login);
  dom["login-tab"].setAttribute("aria-selected", String(login));
  dom["register-tab"].setAttribute("aria-selected", String(!login));
  dom["login-panel"].hidden = !login;
  dom["register-panel"].hidden = login;
  clearGlobalAlert();
}

async function detectCryptoSupport() {
  let errorMessage = "Clave necesita Web Crypto, X25519 y Ed25519 para crear o leer mensajes cifrados.";
  try {
    if (!globalThis.isSecureContext || !globalThis.crypto || !crypto.subtle) {
      throw new Error("Web Crypto solo está disponible en un contexto seguro (HTTPS o localhost).");
    }
    const xPair = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
    await crypto.subtle.exportKey("raw", xPair.publicKey);
    const edPair = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
    await crypto.subtle.exportKey("raw", edPair.publicKey);
    state.cryptoReady = true;
    dom["security-warning"].hidden = true;
  } catch (error) {
    state.cryptoReady = false;
    errorMessage = `${errorMessage} ${error.message || "Actualiza tu navegador o usa una versión reciente de Chromium/Firefox."}`;
    dom["security-warning-text"].textContent = errorMessage;
    dom["security-warning"].hidden = false;
  }
  updateAuthControls();
}

function updateAuthControls() {
  const submitButtons = document.querySelectorAll(".auth-form button[type=submit]");
  for (const button of submitButtons) button.disabled = !state.cryptoReady || !state.dbReady;
  if (!state.cryptoReady) {
    dom["login-help"].textContent = "El navegador no soporta las primitivas criptográficas requeridas.";
  }
}

// IndexedDB keeps CryptoKey objects directly. Private keys are generated non-extractable
// and are never converted to base64 or sent in a request.
function openDatabase() {
  return new Promise((resolve, reject) => {
    if (!globalThis.indexedDB) {
      reject(new Error("IndexedDB no está disponible."));
      return;
    }
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains("identities")) database.createObjectStore("identities", { keyPath: "username" });
      if (!database.objectStoreNames.contains("peers")) database.createObjectStore("peers", { keyPath: "username" });
      if (!database.objectStoreNames.contains("replay")) database.createObjectStore("replay", { keyPath: "id" });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error("Error abriendo IndexedDB."));
  });
}

async function idbGet(storeName, key) {
  const database = await dbPromise;
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(storeName, "readonly");
    const request = transaction.objectStore(storeName).get(key);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function idbPut(storeName, value) {
  const database = await dbPromise;
  return new Promise((resolve, reject) => {
    const transaction = database.transaction(storeName, "readwrite");
    transaction.objectStore(storeName).put(value);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error || new Error("Transacción abortada."));
  });
}

function utf8(value) {
  return new TextEncoder().encode(value);
}

function bytesToBase64(value) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = "";
  const chunk = 0x8000;
  for (let index = 0; index < bytes.length; index += chunk) {
    binary += String.fromCharCode(...bytes.subarray(index, Math.min(index + chunk, bytes.length)));
  }
  return btoa(binary);
}

function base64ToBytes(value) {
  if (typeof value !== "string" || !value) throw new Error("Codificación base64 ausente.");
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function makeMessageId() {
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  return bytesToBase64(randomBytes(16)).replaceAll("/", "_").replaceAll("+", "-").replaceAll("=", "");
}

function canonicalEnvelope(envelope) {
  // Keep this order stable: it is the authenticated representation shared by both clients.
  return JSON.stringify({
    version: envelope.version,
    algorithm: envelope.algorithm,
    from: envelope.from,
    to: envelope.to,
    timestamp: envelope.timestamp,
    msg_id: envelope.msg_id,
    ephemeral_public_key: envelope.ephemeral_public_key,
    salt: envelope.salt,
    iv: envelope.iv,
    ciphertext: envelope.ciphertext,
  });
}

async function generateIdentity(username) {
  const exchange = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  const signing = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  const exchangePublic = bytesToBase64(await crypto.subtle.exportKey("raw", exchange.publicKey));
  const signingPublic = bytesToBase64(await crypto.subtle.exportKey("raw", signing.publicKey));
  return {
    username,
    exchangePrivate: exchange.privateKey,
    signingPrivate: signing.privateKey,
    exchangePublic: exchangePublic,
    signingPublic: signingPublic,
  };
}

async function importExchangePublic(encoded) {
  return crypto.subtle.importKey("raw", base64ToBytes(encoded), { name: "X25519" }, false, []);
}

async function importSigningPublic(encoded) {
  return crypto.subtle.importKey("raw", base64ToBytes(encoded), { name: "Ed25519" }, false, ["verify"]);
}

async function deriveAesKey(sharedSecret, salt, from, to, messageId) {
  const hkdfKey = await crypto.subtle.importKey("raw", sharedSecret, { name: "HKDF" }, false, ["deriveKey"]);
  const info = utf8(`clave-e2ee-v1|${from}|${to}|${messageId}`);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function fingerprintFor(username, exchangePublic, signingPublic) {
  const digest = await crypto.subtle.digest("SHA-256", utf8(`${username}|${exchangePublic}|${signingPublic}`));
  const hex = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0").toUpperCase());
  return hex.join("").match(/.{1,4}/g).join(" ");
}

function normalizeKeys(value, username) {
  const source = value && value.keys ? value.keys : value;
  const exchange = source && (source.exchange_public_key || source.exchangePublicKey || source.x25519_public_key || source.x25519_pub);
  const signing = source && (source.signing_public_key || source.signingPublicKey || source.ed25519_public_key || source.ed25519_pub);
  if (!username || typeof exchange !== "string" || typeof signing !== "string") {
    throw new Error("El servidor no entregó las claves públicas completas del contacto.");
  }
  return { username, exchangePublic: exchange, signingPublic: signing };
}

async function loadPeer(username, suppliedKeys) {
  let keyData = suppliedKeys;
  if (!keyData) {
    const response = await api(`/api/users/${encodeURIComponent(username)}/keys`);
    keyData = normalizeKeys(response, username);
  } else if (!keyData.exchangePublic) {
    keyData = normalizeKeys(keyData, username);
  }
  const stored = await idbGet("peers", username);
  if (stored && (stored.exchangePublic !== keyData.exchangePublic || stored.signingPublic !== keyData.signingPublic)) {
    throw new Error("La clave pública de este contacto cambió. El envío está bloqueado hasta resolver el posible ataque de sustitución.");
  }
  const peer = {
    username,
    exchangePublic: keyData.exchangePublic,
    signingPublic: keyData.signingPublic,
    fingerprint: stored?.fingerprint || await fingerprintFor(username, keyData.exchangePublic, keyData.signingPublic),
    verified: Boolean(stored?.verified),
  };
  await idbPut("peers", peer);
  state.peers.set(username, peer);
  return peer;
}

async function encryptMessage(peer, plaintext) {
  const ephemeral = await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  const recipientPublic = await importExchangePublic(peer.exchangePublic);
  const shared = await crypto.subtle.deriveBits({ name: "X25519", public: recipientPublic }, ephemeral.privateKey, 256);
  const timestamp = Date.now();
  const msgId = makeMessageId();
  const salt = randomBytes(32);
  const iv = randomBytes(12);
  const aesKey = await deriveAesKey(shared, salt, state.username, peer.username, msgId);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, utf8(plaintext));
  const envelope = {
    version: 1,
    algorithm: ALGORITHM_LABEL,
    from: state.username,
    to: peer.username,
    timestamp,
    msg_id: msgId,
    ephemeral_public_key: bytesToBase64(await crypto.subtle.exportKey("raw", ephemeral.publicKey)),
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(ciphertext),
  };
  const signature = await crypto.subtle.sign({ name: "Ed25519" }, state.identity.signingPrivate, utf8(canonicalEnvelope(envelope)));
  envelope.signature = bytesToBase64(signature);
  return envelope;
}

async function decryptMessage(peer, envelope) {
  validateEnvelope(envelope);
  if (envelope.to !== state.username || envelope.from !== peer.username) throw new Error("Destinatario o remitente inválido.");
  const now = Date.now();
  const messageTime = timestampMillis(envelope.timestamp);
  if (!Number.isFinite(messageTime)) {
    throw new Error("Mensaje rechazado por timestamp inválido.");
  }
  if (messageTime - now > MAX_FUTURE_SKEW_MS) {
    throw new Error("Mensaje rechazado porque su timestamp está más de 5 minutos en el futuro.");
  }
  if (now - messageTime > MAX_MESSAGE_AGE_MS) {
    throw new Error("Mensaje rechazado porque tiene más de 30 días.");
  }
  if (state.replay.has(envelope.msg_id) || await idbGet("replay", envelope.msg_id)) {
    throw new Error("Mensaje repetido rechazado (replay).");
  }
  const signingPublic = await importSigningPublic(peer.signingPublic);
  const valid = await crypto.subtle.verify(
    { name: "Ed25519" },
    signingPublic,
    base64ToBytes(envelope.signature),
    utf8(canonicalEnvelope(envelope)),
  );
  if (!valid) throw new Error("Firma Ed25519 inválida.");
  const senderEphemeral = await crypto.subtle.importKey("raw", base64ToBytes(envelope.ephemeral_public_key), { name: "X25519" }, false, []);
  const shared = await crypto.subtle.deriveBits({ name: "X25519", public: senderEphemeral }, state.identity.exchangePrivate, 256);
  const salt = base64ToBytes(envelope.salt);
  const iv = base64ToBytes(envelope.iv);
  const aesKey = await deriveAesKey(shared, salt, envelope.from, envelope.to, envelope.msg_id);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, base64ToBytes(envelope.ciphertext));
  // Only consume a replay identifier after signature verification and successful decryption.
  // A forged envelope must not be able to poison the legitimate message's cache entry.
  if (state.replay.has(envelope.msg_id) || await idbGet("replay", envelope.msg_id)) {
    throw new Error("Mensaje repetido rechazado (replay).");
  }
  await idbPut("replay", { id: envelope.msg_id, seenAt: now });
  state.replay.add(envelope.msg_id);
  return new TextDecoder().decode(plaintext);
}

function timestampMillis(value) {
  if (!Number.isFinite(value)) return Number.NaN;
  // Accept seconds from older Python clients while emitting milliseconds ourselves.
  return value < 1_000_000_000_000 ? value * 1000 : value;
}

function validateEnvelope(envelope) {
  if (!envelope || typeof envelope !== "object") throw new Error("Sobre cifrado inválido.");
  const required = ["version", "algorithm", "from", "to", "timestamp", "msg_id", "ephemeral_public_key", "salt", "iv", "ciphertext", "signature"];
  if (envelope.version !== 1 || required.some((field) => !(field in envelope))) throw new Error("Sobre cifrado incompleto.");
  if (envelope.algorithm !== ALGORITHM_LABEL) throw new Error("Algoritmo de sobre no permitido.");
}

async function handleLogin(event) {
  event.preventDefault();
  if (!state.cryptoReady || !state.dbReady) return;
  const form = new FormData(event.currentTarget);
  const username = String(form.get("username") || "").trim();
  const password = String(form.get("password") || "");
  await withButtonBusy(event.submitter, async () => {
    try {
      const response = await api("/api/login", { method: "POST", auth: false, body: { username, password } });
      const token = response.token || response.access_token;
      if (!token) throw new Error("El servidor no devolvió un token de sesión.");
      const identity = await idbGet("identities", username);
      if (!identity) throw new Error("Esta cuenta no tiene claves privadas en este dispositivo. Regístrate aquí o recupera una copia segura de la identidad.");
      state.token = token;
      state.username = username;
      state.identity = identity;
      await enterApp();
    } catch (error) {
      state.token = null;
      setGlobalAlert(humanError(error), "danger");
    }
  });
}

async function handleRegister(event) {
  event.preventDefault();
  if (!state.cryptoReady || !state.dbReady) return;
  const form = new FormData(event.currentTarget);
  const username = String(form.get("username") || "").trim();
  const password = String(form.get("password") || "");
  const confirmation = String(form.get("password_confirm") || "");
  if (password !== confirmation) {
    setGlobalAlert("Las contraseñas no coinciden.", "danger");
    return;
  }
  if (password.length < 12) {
    setGlobalAlert("La contraseña debe tener al menos 12 caracteres.", "danger");
    return;
  }
  await withButtonBusy(event.submitter, async () => {
    try {
      const identity = await generateIdentity(username);
      await api("/api/register", {
        method: "POST",
        auth: false,
        body: {
          username,
          password,
          exchange_public_key: identity.exchangePublic,
          signing_public_key: identity.signingPublic,
        },
      });
      await idbPut("identities", identity);
      event.currentTarget.reset();
      setAuthTab("login");
      document.getElementById("login-username").value = username;
      setGlobalAlert("Cuenta creada. Ya puedes iniciar sesión desde este dispositivo.", "success");
    } catch (error) {
      setGlobalAlert(humanError(error), "danger");
    }
  });
}

async function enterApp() {
  const me = await api("/api/me");
  const serverUsername = me?.username || me?.user?.username;
  if (serverUsername && serverUsername !== state.username) {
    throw new Error("La identidad de la sesión no coincide con la cuenta local.");
  }
  dom["auth-view"].hidden = true;
  dom["app-view"].hidden = false;
  dom["current-username"].textContent = state.username;
  setConnectionStatus("reconnecting");
  await refreshUsers(false);
  try {
    await connectSocket();
  } catch (error) {
    setGlobalAlert(`Sesión iniciada, pero no se pudo abrir el canal en tiempo real: ${humanError(error)}`, "warning");
  }
}

async function refreshUsers(showFeedback) {
  if (!state.token) return;
  try {
    const response = await api("/api/users");
    const list = Array.isArray(response) ? response : (response.users || response.items || []);
    state.users = list.map((item) => {
      if (typeof item === "string") return { username: item };
      const username = item.username || item.name;
      const hasKeys = item.exchange_public_key && (item.signing_public_key || item.ed25519_public_key);
      return { username, keys: hasKeys ? normalizeKeys(item, username) : null };
    }).filter((item) => item.username && item.username !== state.username);
    renderContacts();
    if (showFeedback) setGlobalAlert("Contactos actualizados.", "success");
  } catch (error) {
    if (showFeedback) setGlobalAlert(`No se pudieron cargar los contactos: ${humanError(error)}`, "danger");
    dom["contacts-list"].replaceChildren(makeText("No se pudieron cargar los contactos."));
  }
}

function renderContacts() {
  const query = dom["contact-search"].value.trim().toLowerCase();
  const users = state.users.filter((user) => user.username.toLowerCase().includes(query));
  dom["contacts-list"].replaceChildren();
  if (!users.length) {
    dom["contacts-list"].append(makeText(query ? "No hay coincidencias." : "No hay otros usuarios registrados."));
    return;
  }
  for (const user of users) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "contact-item";
    button.classList.toggle("is-selected", state.activePeer?.username === user.username);
    button.setAttribute("role", "listitem");
    const avatar = document.createElement("span");
    avatar.className = "avatar";
    avatar.setAttribute("aria-hidden", "true");
    avatar.textContent = user.username.slice(0, 1).toUpperCase();
    const info = document.createElement("span");
    info.className = "contact-item-info";
    const name = document.createElement("span");
    name.className = "contact-name";
    name.textContent = user.username;
    const meta = document.createElement("span");
    meta.className = "contact-meta";
    const peer = state.peers.get(user.username);
    meta.textContent = peer?.verified ? "Huella verificada" : "Huella pendiente";
    info.append(name, meta);
    button.append(avatar, info);
    button.addEventListener("click", () => selectPeer(user));
    dom["contacts-list"].append(button);
  }
}

async function selectPeer(user) {
  clearChatAlert();
  dom["no-chat-state"].hidden = true;
  dom["active-chat"].hidden = false;
  dom["chat-title"].textContent = user.username;
  dom["chat-avatar"].textContent = user.username.slice(0, 1).toUpperCase();
  dom["chat-key-status"].textContent = "Consultando identidad…";
  dom["message-input"].disabled = true;
  dom["send-button"].disabled = true;
  dom["fingerprint-panel"].hidden = true;
  try {
    state.activePeer = await loadPeer(user.username, user.keys);
    renderActivePeer();
    renderMessages();
  } catch (error) {
    state.activePeer = null;
    dom["chat-key-status"].textContent = "Identidad no disponible";
    showChatAlert(humanError(error));
  }
  renderContacts();
}

function renderActivePeer() {
  const peer = state.activePeer;
  if (!peer) return;
  dom["chat-key-status"].textContent = peer.verified ? "Huella verificada fuera de banda" : "Verifica la huella antes de enviar";
  dom["chat-key-status"].classList.toggle("is-verified", peer.verified);
  dom["chat-key-status"].classList.toggle("is-warning", !peer.verified);
  dom["message-input"].disabled = !peer.verified || !isSocketOpen();
  dom["send-button"].disabled = !peer.verified || !isSocketOpen();
  dom["fingerprint-value"].textContent = peer.fingerprint;
  dom["fingerprint-description"].textContent = peer.verified
    ? "Esta identidad está fijada localmente y fue marcada como verificada por ti."
    : "Compara esta huella con tu contacto por otro canal confiable antes de marcarla como verificada.";
  renderFingerprintAction();
}

function renderFingerprintAction() {
  const peer = state.activePeer;
  dom["fingerprint-action"].replaceChildren();
  if (!peer) return;
  if (peer.verified) {
    const text = document.createElement("p");
    text.className = "muted";
    text.textContent = "✓ Verificada en este dispositivo. Si cambia, el envío se bloqueará.";
    dom["fingerprint-action"].append(text);
    return;
  }
  const label = document.createElement("label");
  const checkbox = document.createElement("input");
  checkbox.type = "checkbox";
  checkbox.id = "fingerprint-confirmation";
  const labelText = document.createElement("span");
  labelText.textContent = "He comparado la huella con mi contacto por otro canal.";
  label.append(checkbox, labelText);
  const button = document.createElement("button");
  button.type = "button";
  button.className = "button button-primary";
  button.style.marginTop = "10px";
  button.textContent = "Marcar como verificada";
  button.disabled = true;
  checkbox.addEventListener("change", () => { button.disabled = !checkbox.checked; });
  button.addEventListener("click", async () => {
    peer.verified = true;
    await idbPut("peers", peer);
    state.peers.set(peer.username, peer);
    renderActivePeer();
    renderContacts();
    showChatAlert("Huella verificada. Ya puedes enviar mensajes cifrados.", "success");
  });
  dom["fingerprint-action"].append(label, button);
}

function renderMessages() {
  dom["message-list"].replaceChildren();
  if (!state.activePeer) return;
  const messages = state.messages.get(state.activePeer.username) || [];
  if (!messages.length) {
    const empty = document.createElement("p");
    empty.className = "message-empty";
    empty.textContent = "Aún no hay mensajes. La conversación se cifrará en tu dispositivo.";
    dom["message-list"].append(empty);
    return;
  }
  for (const message of messages) {
    const article = document.createElement("article");
    article.className = `message ${message.direction === "out" ? "message-out" : "message-in"}`;
    const body = document.createElement("p");
    body.className = "message-body";
    body.textContent = message.text;
    const time = document.createElement("time");
    time.className = "message-time";
    time.dateTime = new Date(message.timestamp).toISOString();
    time.textContent = formatTime(message.timestamp);
    article.append(body, time);
    dom["message-list"].append(article);
  }
  dom["message-list"].scrollTop = dom["message-list"].scrollHeight;
}

async function handleSendMessage(event) {
  event.preventDefault();
  const plaintext = dom["message-input"].value.trim();
  if (!plaintext || !state.activePeer) return;
  if (!state.activePeer.verified) {
    dom["fingerprint-panel"].hidden = false;
    showChatAlert("Verifica la huella fuera de banda antes de enviar.");
    return;
  }
  if (!isSocketOpen()) {
    showChatAlert("El canal no está conectado. Espera a que vuelva a estar disponible.");
    return;
  }
  await withButtonBusy(dom["send-button"], async () => {
    try {
      const envelope = await encryptMessage(state.activePeer, plaintext);
      state.socket.send(JSON.stringify({ type: "message", recipient: state.activePeer.username, envelope }));
      state.ownMessageIds.add(envelope.msg_id);
      appendMessage(state.activePeer.username, { direction: "out", text: plaintext, timestamp: envelope.timestamp, msgId: envelope.msg_id });
      dom["message-input"].value = "";
      resizeComposer();
      clearChatAlert();
    } catch (error) {
      showChatAlert(`No se pudo cifrar o enviar: ${humanError(error)}`);
    }
  });
}

function appendMessage(username, message) {
  if (!state.messages.has(username)) state.messages.set(username, []);
  state.messages.get(username).push(message);
  if (state.activePeer?.username === username) renderMessages();
}

async function connectSocket() {
  if (!state.token) return;
  if (state.socket && state.socketReady && isSocketOpen()) return;
  if (state.reconnectTimer) {
    clearTimeout(state.reconnectTimer);
    state.reconnectTimer = null;
  }
  const generation = ++state.socketGeneration;
  const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
  const socket = new WebSocket(`${scheme}//${window.location.host}/ws`);
  state.socket = socket;
  state.socketReady = false;
  state.socketQueue = [];
  setConnectionStatus("reconnecting");

  let handshakeSettled = false;
  let handshakeResolve;
  let handshakeReject;
  const handshake = new Promise((resolve, reject) => {
    handshakeResolve = resolve;
    handshakeReject = reject;
  });
  const failHandshake = (message) => {
    if (handshakeSettled) return;
    handshakeSettled = true;
    if (state.socket === socket && generation === state.socketGeneration) state.socketReady = false;
    handshakeReject(new Error(message));
  };
  const completeHandshake = () => {
    if (handshakeSettled || state.socket !== socket || !state.token) return;
    handshakeSettled = true;
    state.socketReady = true;
    setConnectionStatus("online");
    renderActivePeer();
    handshakeResolve();
    const queued = state.socketQueue.splice(0);
    for (const queuedMessage of queued) {
      handleIncoming(queuedMessage).catch((error) => console.warn("Mensaje entrante rechazado", error));
    }
  };

  // Install message/close/error listeners immediately after construction. The
  // server may send ready and queued messages as soon as the socket opens.
  socket.addEventListener("message", (event) => {
    const message = parseSocketPayload(event.data);
    if (!message) return;
    if (message.type === "ready") {
      completeHandshake();
      return;
    }
    if (!state.socketReady && (message.type === "error" || message.type === "auth_error")) {
      failHandshake(message.error || message.detail || "El servidor rechazó la autenticación del WebSocket.");
      if (socket.readyState === WebSocket.OPEN) socket.close();
      return;
    }
    if (!state.socketReady) {
      state.socketQueue.push(message);
      return;
    }
    handleIncoming(message).catch((error) => {
      console.warn("Mensaje entrante rechazado", error);
    });
  });
  socket.addEventListener("open", () => {
    try {
      socket.send(JSON.stringify({ type: "auth", token: state.token }));
    } catch {
      failHandshake("No se pudo enviar la autenticación del WebSocket.");
    }
  }, { once: true });
  socket.addEventListener("error", () => {
    if (state.socket !== socket || generation !== state.socketGeneration || !state.token) return;
    failHandshake("WebSocket no pudo completar la autenticación.");
  });
  socket.addEventListener("close", () => {
    if (state.socket !== socket || generation !== state.socketGeneration || !state.token) return;
    state.socketReady = false;
    state.socketQueue = [];
    failHandshake("El WebSocket se cerró durante la autenticación.");
    setConnectionStatus("offline");
    renderActivePeer();
    state.reconnectTimer = window.setTimeout(() => connectSocket().catch(() => {}), 3000);
  });
  const handshakeTimeout = window.setTimeout(() => {
    failHandshake("El servidor no confirmó la autenticación del WebSocket.");
    if (socket.readyState === WebSocket.OPEN) socket.close();
  }, 10000);
  try {
    await handshake;
  } finally {
    window.clearTimeout(handshakeTimeout);
  }
}

function parseSocketPayload(raw) {
  try {
    return typeof raw === "string" ? JSON.parse(raw) : raw;
  } catch {
    return null;
  }
}

async function handleIncoming(raw) {
  let message;
  try {
    message = typeof raw === "string" ? JSON.parse(raw) : raw;
  } catch {
    return;
  }
  if (!message || (message.type !== "message" && message.type !== "msg")) return;
  const deliveryId = message.id ?? message.message_id ?? message.msg_id;
  let sender;
  let processed = false;
  try {
    // The API's current shape is message_id/from/envelope. Keep accepting the
    // original id/sender names and common wrapper aliases during migration.
    sender = message.sender ?? message.from ?? message.sender_username;
    let envelope = message.envelope ?? message.payload ?? message.data ?? message.message;
    if (typeof envelope === "string") envelope = JSON.parse(envelope);
    validateEnvelope(envelope);
    if (envelope.from === state.username) return;
    if (!sender || sender !== envelope.from) throw new Error("Remitente inconsistente.");
    const recipient = message.recipient ?? message.to;
    if (recipient && recipient !== state.username) throw new Error("Destinatario inconsistente.");
    let peer = state.peers.get(envelope.from);
    if (!peer) peer = await loadPeer(envelope.from);
    const plaintext = await decryptMessage(peer, envelope);
    appendMessage(peer.username, { direction: "in", text: plaintext, timestamp: timestampMillis(envelope.timestamp), msgId: envelope.msg_id });
    processed = true;
    if (state.activePeer?.username !== peer.username) {
      setGlobalAlert(`Nuevo mensaje cifrado de ${peer.username}.`, "success");
    }
    if (!peer.verified) {
      setGlobalAlert(`Mensaje recibido de ${peer.username}. Verifica su huella antes de responder.`, "warning");
    }
  } catch (error) {
    if (state.activePeer?.username === sender) showChatAlert(`Mensaje rechazado: ${humanError(error)}`);
  } finally {
    // Confirm only after successful signature verification and decryption.
    // A transient key/network/storage failure must leave the ciphertext queued.
    if (processed && deliveryId && isSocketOpen()) {
      state.socket.send(JSON.stringify({ type: "ack", message_id: deliveryId }));
    }
  }
}

function logout() {
  state.token = null;
  state.username = null;
  state.identity = null;
  state.activePeer = null;
  state.users = [];
  state.peers.clear();
  state.messages.clear();
  state.replay.clear();
  state.ownMessageIds.clear();
  if (state.reconnectTimer) clearTimeout(state.reconnectTimer);
  state.reconnectTimer = null;
  state.socketGeneration += 1;
  state.socketReady = false;
  state.socketQueue = [];
  if (state.socket) state.socket.close();
  state.socket = null;
  dom["app-view"].hidden = true;
  dom["auth-view"].hidden = false;
  dom["login-panel"].reset();
  dom["register-panel"].reset();
  dom["no-chat-state"].hidden = false;
  dom["active-chat"].hidden = true;
  setConnectionStatus("offline");
  clearGlobalAlert();
  setAuthTab("login");
}

async function api(path, options = {}) {
  const headers = { Accept: "application/json" };
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (options.auth !== false && state.token) headers.Authorization = `Bearer ${state.token}`;
  const response = await fetch(path, {
    method: options.method || "GET",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    credentials: "same-origin",
  });
  const contentType = response.headers.get("content-type") || "";
  const data = contentType.includes("json") ? await response.json() : await response.text();
  if (!response.ok) {
    const message = typeof data === "object" ? (data.detail || data.error || data.message) : data;
    const error = new Error(message || `Solicitud fallida (${response.status}).`);
    error.status = response.status;
    throw error;
  }
  return data;
}

function isSocketOpen() {
  return Boolean(state.socket && state.socketReady && state.socket.readyState === WebSocket.OPEN);
}

function setConnectionStatus(status) {
  const labels = { online: "Conectado", offline: "Desconectado", reconnecting: "Conectando…" };
  const element = dom["connection-status"];
  element.className = `status-pill status-${status}`;
  element.replaceChildren();
  const dot = document.createElement("span");
  dot.className = "status-dot";
  dot.setAttribute("aria-hidden", "true");
  const text = document.createElement("span");
  text.textContent = labels[status] || labels.offline;
  element.append(dot, text);
}

function resizeComposer() {
  const input = dom["message-input"];
  input.style.height = "auto";
  input.style.height = `${Math.min(input.scrollHeight, 140)}px`;
}

function formatTime(timestamp) {
  return new Intl.DateTimeFormat("es-PE", { hour: "2-digit", minute: "2-digit" }).format(new Date(timestamp));
}

function makeText(text) {
  const paragraph = document.createElement("p");
  paragraph.className = "empty-state";
  paragraph.textContent = text;
  return paragraph;
}

function setGlobalAlert(message, type = "danger") {
  dom["global-alert"].className = `alert alert-${type}`;
  dom["global-alert"].textContent = message;
  dom["global-alert"].hidden = false;
}

function clearGlobalAlert() {
  dom["global-alert"].hidden = true;
  dom["global-alert"].textContent = "";
}

function showChatAlert(message, type = "danger") {
  dom["chat-alert"].className = `chat-alert ${type === "success" ? "alert-success" : ""}`;
  dom["chat-alert"].textContent = message;
  dom["chat-alert"].hidden = false;
}

function clearChatAlert() {
  dom["chat-alert"].hidden = true;
  dom["chat-alert"].textContent = "";
}

function humanError(error) {
  const text = error?.message || String(error);
  if (text.includes("Failed to fetch")) return "No se pudo contactar al servidor.";
  return text;
}

async function withButtonBusy(button, action) {
  if (!button) return action();
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "Procesando…";
  try {
    await action();
  } finally {
    button.textContent = original;
    button.disabled = false;
    if (button === dom["send-button"]) renderActivePeer();
  }
}
