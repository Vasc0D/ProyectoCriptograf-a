#!/usr/bin/env bash
set -Eeuo pipefail

# Crea un backup cifrado con AES-256-CBC + PBKDF2. El archivo temporal sin
# cifrar se elimina al terminar y nunca se conserva en el directorio de salida.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
DATA_DIR="${DATA_DIR:-$PROJECT_ROOT/data}"
LOG_DIR="${LOG_DIR:-$PROJECT_ROOT/logs}"
BACKUP_DIR="${BACKUP_DIR:-$PROJECT_ROOT/backups}"
PBKDF2_ITERATIONS="${PBKDF2_ITERATIONS:-600000}"

if [[ $# -gt 1 ]]; then
  printf 'Uso: %s [directorio_salida]\n' "$0" >&2
  exit 2
fi
if [[ $# -eq 1 ]]; then BACKUP_DIR="$1"; fi
if [[ "$BACKUP_DIR" == "/" || "$BACKUP_DIR" == "$PROJECT_ROOT" ]]; then
  printf 'Error: directorio de backups demasiado amplio o inseguro.\n' >&2
  exit 1
fi
for required in openssl tar shasum; do
  if ! command -v "$required" >/dev/null 2>&1; then
    printf 'Error: falta la herramienta requerida: %s\n' "$required" >&2
    exit 1
  fi
done
if ! [[ "$PBKDF2_ITERATIONS" =~ ^[0-9]+$ ]] || (( PBKDF2_ITERATIONS < 100000 )); then
  printf 'Error: PBKDF2_ITERATIONS debe ser un entero >= 100000.\n' >&2
  exit 1
fi

umask 077
mkdir -p -- "$BACKUP_DIR"

passphrase="${BACKUP_PASSPHRASE:-}"
if [[ -z "$passphrase" ]]; then
  if [[ -t 0 ]]; then
    read -r -s -p 'Passphrase del backup (no se guarda): ' passphrase
    printf '\n'
    read -r -s -p 'Repite la passphrase: ' passphrase_confirm
    printf '\n'
    if [[ -z "$passphrase" || "$passphrase" != "$passphrase_confirm" ]]; then
      printf 'Error: passphrases vacías o no coincidentes.\n' >&2
      exit 1
    fi
    unset passphrase_confirm
  else
    printf 'Error: define BACKUP_PASSPHRASE mediante un gestor de secretos en modo no interactivo.\n' >&2
    exit 1
  fi
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
archive="$BACKUP_DIR/chat-backup-$stamp.tar.gz.enc"
manifest="$BACKUP_DIR/chat-backup-$stamp.manifest"
staging="$(mktemp -d "${TMPDIR:-/tmp}/chat-backup.XXXXXX")"
plain_archive="$staging/payload.tar.gz"
trap 'rm -rf -- "$staging"; unset passphrase' EXIT

mkdir -p "$staging/payload"
if [[ -d "$DATA_DIR" ]]; then cp -a -- "$DATA_DIR" "$staging/payload/data"; fi
if [[ -d "$LOG_DIR" ]]; then cp -a -- "$LOG_DIR" "$staging/payload/logs"; fi

# La lista explícita evita capturar .env, certificados, claves privadas y
# almacenes de claves aunque alguien los coloque accidentalmente bajo data/logs.
tar -czf "$plain_archive" -C "$staging" \
  --exclude='*.key' --exclude='*.key.pem' --exclude='*.pem' \
  --exclude='*.p12' --exclude='*.pfx' --exclude='.env' --exclude='.keys' payload

# La passphrase viaja por stdin de OpenSSL y nunca por argumentos de proceso.
printf '%s' "$passphrase" | openssl enc -aes-256-cbc -pbkdf2 \
  -iter "$PBKDF2_ITERATIONS" -md sha256 -salt -pass stdin \
  -in "$plain_archive" -out "$archive"
chmod 600 "$archive"

{
  printf 'created_at_utc=%s\n' "$stamp"
  printf 'encryption=AES-256-CBC-PBKDF2-SHA256\n'
  printf 'pbkdf2_iterations=%s\n' "$PBKDF2_ITERATIONS"
  printf 'source_data=%s\n' "$DATA_DIR"
  printf 'source_logs=%s\n' "$LOG_DIR"
  printf 'archive=%s\n' "$archive"
  printf 'contents_after_decryption:\n'
  tar -tzf "$plain_archive"
} >"$manifest"
chmod 600 "$manifest"

(cd "$(dirname -- "$archive")" && shasum -a 256 "$(basename -- "$archive")") >"$archive.sha256"
chmod 600 "$archive.sha256"

printf 'Backup cifrado creado: %s\nManifest: %s\nSHA-256: %s\n' "$archive" "$manifest" "$archive.sha256"
