#!/usr/bin/env bash
set -Eeuo pipefail

# Descifra a un temporal, valida el contenido y restaura en un directorio nuevo.
# Nunca sobrescribe el estado activo.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
PBKDF2_ITERATIONS="${PBKDF2_ITERATIONS:-600000}"

if [[ $# -lt 1 || $# -gt 2 || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  printf 'Uso: %s BACKUP.tar.gz.enc [directorio_restauracion]\n' "$0"
  exit 2
fi
archive="$1"
if [[ ! -f "$archive" ]]; then
  printf 'Error: backup no encontrado: %s\n' "$archive" >&2
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
if [[ ! -f "$archive.sha256" ]]; then
  printf 'Error: falta el checksum del artefacto cifrado: %s.sha256\n' "$archive" >&2
  exit 1
fi
(cd "$(dirname -- "$archive")" && shasum -a 256 -c "$(basename -- "$archive.sha256")")

passphrase="${BACKUP_PASSPHRASE:-}"
if [[ -z "$passphrase" ]]; then
  if [[ -t 0 ]]; then
    read -r -s -p 'Passphrase del backup (no se guarda): ' passphrase
    printf '\n'
  else
    printf 'Error: define BACKUP_PASSPHRASE mediante un gestor de secretos en modo no interactivo.\n' >&2
    exit 1
  fi
fi

target="${2:-$PROJECT_ROOT/restore-$(date -u +%Y%m%dT%H%M%SZ)}"
if [[ "$target" == "/" || "$target" == "$PROJECT_ROOT" || -e "$target" ]]; then
  printf 'Error: el destino debe ser un directorio nuevo y específico: %s\n' "$target" >&2
  exit 1
fi

staging="$(mktemp -d "${TMPDIR:-/tmp}/chat-restore.XXXXXX")"
plain_archive="$staging/payload.tar.gz"
trap 'rm -rf -- "$staging"; unset passphrase' EXIT

# OpenSSL descifra el artefacto verificado; una passphrase errónea detiene el flujo.
if ! printf '%s' "$passphrase" | openssl enc -d -aes-256-cbc -pbkdf2 \
    -iter "$PBKDF2_ITERATIONS" -md sha256 -pass stdin \
    -in "$archive" -out "$plain_archive"; then
  printf 'Error: no se pudo descifrar el backup (passphrase o archivo inválido).\n' >&2
  exit 1
fi

# Bloquear traversal y rutas absolutas antes de extraer un archivo no confiable.
while IFS= read -r entry; do
  entry="${entry#./}"
  if [[ "$entry" == /* || "$entry" == .. || "$entry" == ../* || "$entry" == */../* || "$entry" == */.. ]]; then
    printf 'Error: el backup contiene una ruta insegura: %s\n' "$entry" >&2
    exit 1
  fi
done < <(tar -tzf "$plain_archive")

# Rechazar symlinks/hardlinks para evitar que un archivo del tar escape del destino.
while IFS= read -r listing; do
  kind="${listing:0:1}"
  if [[ "$kind" == "l" || "$kind" == "h" ]]; then
    printf 'Error: no se permiten enlaces en el backup: %s\n' "$listing" >&2
    exit 1
  fi
done < <(tar -tvzf "$plain_archive")

umask 077
mkdir -p -- "$target"
tar -xzf "$plain_archive" -C "$target" --no-same-owner --no-same-permissions
chmod -R go-rwx "$target"

printf 'Backup descifrado y restaurado de forma no destructiva en: %s\n' "$target"
printf 'Revisa payload/data y payload/logs antes de promoverlos al servicio activo.\n'
