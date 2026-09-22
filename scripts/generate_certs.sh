#!/usr/bin/env bash
set -Eeuo pipefail

# Genera una CA local y un certificado de servidor para desarrollo/demo.
# No debe usarse como PKI pública ni para producción.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${CERT_DIR:-$PROJECT_ROOT/certs}"
FORCE="${FORCE:-0}"
VALID_DAYS="${VALID_DAYS:-825}"
CA_VALID_DAYS="${CA_VALID_DAYS:-3650}"

usage() {
  printf 'Uso: %s [directorio_salida]\n' "$0"
  printf 'Variables: CERT_DIR, FORCE=1, VALID_DAYS, CA_VALID_DAYS\n'
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi
if [[ $# -gt 1 ]]; then
  printf 'Error: se acepta como máximo un directorio de salida.\n' >&2
  usage >&2
  exit 2
fi
if [[ $# -eq 1 ]]; then
  OUT_DIR="$1"
fi
if ! command -v openssl >/dev/null 2>&1; then
  printf 'Error: openssl no está instalado.\n' >&2
  exit 1
fi

umask 077
mkdir -p -- "$OUT_DIR"
for file in ca.key.pem ca.cert.pem server.key.pem server.csr.pem server.cert.pem server-chain.pem; do
  if [[ -e "$OUT_DIR/$file" && "$FORCE" != "1" ]]; then
    printf 'Error: ya existe %s. Usa FORCE=1 solo si deseas regenerar el material.\n' "$OUT_DIR/$file" >&2
    exit 1
  fi
done

passphrase="${CA_PASSPHRASE:-}"
if [[ -z "$passphrase" ]]; then
  if [[ -t 0 ]]; then
    read -r -s -p 'Passphrase para la clave privada de la CA (no se guarda): ' passphrase
    printf '\n'
    read -r -s -p 'Repite la passphrase: ' passphrase_confirm
    printf '\n'
    if [[ "$passphrase" != "$passphrase_confirm" || -z "$passphrase" ]]; then
      printf 'Error: passphrases vacías o no coincidentes.\n' >&2
      exit 1
    fi
    unset passphrase_confirm
  else
    printf 'Error: define CA_PASSPHRASE en modo no interactivo.\n' >&2
    exit 1
  fi
fi

tmp_conf="$(mktemp)"
trap 'rm -f -- "$tmp_conf"' EXIT
cat >"$tmp_conf" <<'EOF'
[ req ]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
C = PE
O = Proyecto Etica y Seguridad
OU = Desarrollo
CN = localhost

[ v3_req ]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

printf '%s\n' "$passphrase" | openssl genpkey -algorithm RSA -aes-256-cbc \
  -pass stdin -pkeyopt rsa_keygen_bits:3072 -out "$OUT_DIR/ca.key.pem"
chmod 600 "$OUT_DIR/ca.key.pem"
printf '%s\n' "$passphrase" | openssl req -x509 -new -sha256 \
  -key "$OUT_DIR/ca.key.pem" -passin stdin -days "$CA_VALID_DAYS" \
  -subj '/C=PE/O=Proyecto Etica y Seguridad/OU=Desarrollo/CN=Proyecto Etica CA' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:1' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -out "$OUT_DIR/ca.cert.pem"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$OUT_DIR/server.key.pem"
chmod 600 "$OUT_DIR/server.key.pem"
openssl req -new -sha256 -key "$OUT_DIR/server.key.pem" \
  -out "$OUT_DIR/server.csr.pem" -config "$tmp_conf"
printf '%s\n' "$passphrase" | openssl x509 -req -sha256 \
  -in "$OUT_DIR/server.csr.pem" -CA "$OUT_DIR/ca.cert.pem" \
  -CAkey "$OUT_DIR/ca.key.pem" -passin stdin -CAcreateserial \
  -out "$OUT_DIR/server.cert.pem" -days "$VALID_DAYS" \
  -extfile "$tmp_conf" -extensions v3_req
cat "$OUT_DIR/server.cert.pem" "$OUT_DIR/ca.cert.pem" >"$OUT_DIR/server-chain.pem"
chmod 644 "$OUT_DIR/ca.cert.pem" "$OUT_DIR/server.cert.pem" "$OUT_DIR/server-chain.pem"
rm -f -- "$OUT_DIR/ca.cert.srl"

printf '\nCertificados creados en %s\n' "$OUT_DIR"
printf 'CA privada: %s (protegida con passphrase; no versionar)\n' "$OUT_DIR/ca.key.pem"
printf 'Servidor:   %s (SAN: localhost, 127.0.0.1, ::1)\n' "$OUT_DIR/server.cert.pem"
openssl x509 -in "$OUT_DIR/server.cert.pem" -noout -subject -issuer -dates -ext subjectAltName
