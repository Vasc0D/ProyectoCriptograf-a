# Clave - mensajeria web cifrada de extremo a extremo

Proyecto academico para el curso de Etica y Seguridad de Datos. La aplicacion
permite registrar usuarios, verificar la identidad de un contacto fuera de
banda y enviar mensajes que se cifran y firman en el navegador. El servidor
solo recibe sobres cifrados y metadatos de entrega.

## Funcionalidad implementada

- Frontend web responsive y accesible, sin dependencias JavaScript externas.
- Registro e inicio de sesion con contrasenas procesadas mediante Argon2id.
- X25519 + HKDF-SHA-256 + AES-256-GCM para cifrar cada mensaje.
- Firmas Ed25519 y un formato canonico firmado para autenticar los sobres.
- Claves privadas cifradas localmente con PBKDF2-SHA-256 (310 000 iteraciones) y AES-256-GCM antes de guardarse en IndexedDB. Al iniciar sesión se importan en memoria como `CryptoKey` no extraíbles.
- Pinning TOFU y verificacion manual de huellas por un canal independiente.
- WebSocket autenticado, mensajes asincronos y entrega *at-least-once* con ACK.
- SQLite para usuarios, claves publicas, sobres cifrados y auditoria sanitizada.
- Proteccion anti-suplantacion, anti-replay, limites de tamano y rate limiting.
- HTTPS/WSS con certificado emitido por una CA local propia.
- Backups cifrados, checksum y restauracion no destructiva.
- Contenedor sin privilegios y con sistema de archivos de solo lectura.

## Arquitectura

```text
Navegador A                 Backend FastAPI                 Navegador B
claves privadas             autenticacion                  claves privadas
cifrado + firma  --WSS-->   cola de sobres cifrados --WSS--> verificacion
                             SQLite + auditoria              descifrado
```

El backend nunca recibe el texto plano ni las claves privadas. Si la base de
datos se filtra, el contenido permanece cifrado, aunque remitente,
destinatario y tiempos de entrega siguen siendo metadatos visibles.

## Inicio rapido

Requiere Python 3.12 o 3.13, OpenSSL y un navegador reciente con Web Crypto,
X25519 y Ed25519.

```bash
python3.13 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp .env.example .env
```

Genera la CA y el certificado del servidor. El script solicita una passphrase
para proteger la clave privada de la CA:

```bash
./scripts/generate_certs.sh
```

Define en `.env` un `SESSION_SECRET` aleatorio y arranca el servidor:

```bash
.venv/bin/uvicorn app.main:app \
  --host 0.0.0.0 --port 8443 --env-file .env \
  --ssl-keyfile certs/server.key.pem \
  --ssl-certfile certs/server-chain.pem
```

Importa `certs/ca.cert.pem` como CA de confianza **solo en el entorno de
laboratorio** y abre `https://localhost:8443`. No ignores advertencias TLS.
Las instrucciones completas y la renovacion de certificados estan en
[`docs/OPERATIONS.md`](docs/OPERATIONS.md).

Tambien puede ejecutarse con Docker:

```bash
docker compose up --build
```

## Pruebas

```bash
SESSION_SECRET='una-clave-de-prueba-de-al-menos-32-bytes' \
  .venv/bin/python -m pytest -q
node --check frontend/app.js
bash -n scripts/*.sh
```

Las pruebas cubren autenticacion, rate limiting, rechazo de suplantacion,
contrato del sobre moderno, cola offline y confirmacion de entrega mediante
ACK.

## Backup y recuperacion

El backup se cifra con AES-256-CBC y PBKDF2 antes de salir del directorio
temporal. Para automatizacion, `BACKUP_PASSPHRASE` debe provenir de un gestor
de secretos, no de `.env` ni del repositorio.

```bash
./scripts/backup.sh
./scripts/restore.sh backups/chat-backup-FECHA.tar.gz.enc
```

La restauracion siempre crea un directorio nuevo y valida checksum, rutas y
enlaces antes de extraer.

## Documentacion de seguridad

- [Informe escrito en Word](docs/Informe_Proyecto_Clave.docx)
- [Informe en Markdown](docs/INFORME.md)
- [Modelo de amenazas](docs/THREAT_MODEL.md)
- [Operacion, TLS, backups y respuesta](docs/OPERATIONS.md)
- [Politica de seguridad](SECURITY.md)

## Limitaciones reconocidas

Este proyecto **no implementa Signal**. No tiene Double Ratchet, prekeys ni
secreto futuro frente al compromiso posterior de la clave privada X25519 del
receptor. Los tokens HMAC expiran, pero no tienen revocacion individual en el
servidor. SQLite y el registro de conexiones en memoria requieren un solo
proceso. La recuperacion de una clave privada perdida no esta implementada.

Estas limitaciones, sus riesgos y las mejoras futuras estan desarrolladas en
el informe y en el modelo de amenazas.

## Codigo anterior

El prototipo de escritorio original se conserva en [`legacy/`](legacy/) solo
como antecedente. La entrega actual se ejecuta desde `app/` y `frontend/`.
