# Runbook de operación

Este documento describe un despliegue de laboratorio reproducible. Completar
las variables específicas del backend si cambian sus nombres. No usar datos
reales ni exponer el servidor de desarrollo a Internet.

## 1. Preflight

```bash
cd ProyectoCriptografia
cp .env.example .env
mkdir -p data logs backups certs
chmod 700 data logs backups certs
```

Antes de iniciar, reemplazar `SESSION_SECRET` por un secreto aleatorio de alta
entropía administrado fuera de Git. El valor de `.env.example` es solo un
marcador académico.

Revisar que `.env` no tenga secretos en Git:

```bash
git status --short
git check-ignore -v .env certs/server.key.pem data logs
```

Instalar dependencias en un entorno virtual según el `requirements.txt` de la
versión final y ejecutar pruebas antes de iniciar el servicio.

## 2. Certificados de laboratorio

La CA privada se crea cifrada y se solicita una passphrase interactiva. La
passphrase no debe pegarse en un issue ni quedar en la shell history.

```bash
./scripts/generate_certs.sh
openssl verify -CAfile certs/ca.cert.pem certs/server.cert.pem
openssl x509 -in certs/server.cert.pem -noout -ext subjectAltName
openssl s_client -connect localhost:8443 -CAfile certs/ca.cert.pem -servername localhost </dev/null 2>/dev/null | grep -E 'Protocol|Cipher'
```

El certificado incluye `localhost`, `127.0.0.1` y `::1`. El runtime debe
negociar TLS 1.2 o superior (preferir TLS 1.3) y se debe anotar el protocolo
efectivamente negociado durante la demo. El navegador debe
confiar explícitamente en `certs/ca.cert.pem` para la demo; nunca activar
"aceptar certificados inseguros" globalmente. Para renovar:

```bash
FORCE=1 ./scripts/generate_certs.sh
```

Antes de renovar en un entorno compartido, anunciar la ventana, comprobar qué
clientes confían en la CA y conservar la CA existente si solo se rota el
certificado de servidor. Regenerar la CA revoca implícitamente todos los
certificados anteriores.

## 3. Ejecución local

El backend web se ejecuta con FastAPI/Uvicorn. La terminación TLS se configura
en Uvicorn con `TLS_CERT_FILE` y `TLS_KEY_FILE`; el frontend se sirve desde
el mismo origen y usa HTTPS/WSS.

```bash
set -a
. ./.env
set +a
uvicorn app.main:app --host "$HOST" --port "$PORT" \
  --ssl-keyfile "$TLS_KEY_FILE" --ssl-certfile "$TLS_CERT_FILE"
```

El proceso no debe ejecutarse como root. Comprobar que el healthcheck sea solo
de disponibilidad, no un endpoint que revele estado sensible.

## 4. Ejecución con Docker Compose

```bash
cp .env.example .env
./scripts/generate_certs.sh
docker compose build
docker compose up -d
docker compose ps
docker compose logs --tail=100 chat-backend
```

El contenedor corre como usuario sin privilegios, con filesystem de solo
lectura, `cap_drop: ALL`, `no-new-privileges`, `/tmp` temporal y volúmenes
separados para estado. Compose arranca `uvicorn app.main:app` con TLS y sirve
el frontend estático que monta FastAPI.

Para detener sin borrar volúmenes:

```bash
docker compose stop
docker compose down
```

No usar `docker compose down -v` en un entorno con datos: elimina volúmenes.

## 5. Usuarios, sesiones y claves

- **Crear cuentas** solo con datos sintéticos de prueba.
- **No reutilizar contraseñas** personales; usar longitud mínima y gestor de
  contraseñas.
- **Invalidar todas las sesiones** tras una sospecha rotando `SESSION_SECRET` y
  reiniciando el servicio. La revocación individual todavía no está implementada.
- **Verificar huellas** con un canal externo antes del primer mensaje sensible.
- **Ante cambio de clave**, pausar el contacto hasta repetir la verificación.
- **Las claves privadas** de cliente no se respaldan automáticamente por el
  servidor. El usuario debe conocer la política de recuperación.

## 6. Logs, métricas y revisión

Revisar periódicamente inicio de sesión fallido, cambios de clave, repetición de
IDs, errores de firma/tag, exceso de rate limit, fallos de backup y reinicios.
El operador debe confirmar que no aparecen plaintext, cookies, tokens o claves.
Rotar/retener según la política del informe y restringir la lectura:

```bash
find logs -type f -maxdepth 1 -exec chmod 600 {} +
```

No ejecutar `tail` ni subir logs sin inspeccionar/redactar datos personales.

## 7. Backup cifrado y restauración

Backup diario (o manual antes de una demo). El script solicita una passphrase
de cifrado interactiva y no la guarda:

```bash
./scripts/backup.sh
ls -l backups
```

Para automatización, se puede proporcionar `BACKUP_PASSPHRASE` desde un gestor
de secretos del job. No exportar la variable desde un archivo versionado ni
ponerla en argumentos visibles. El archivo `.tar.gz.enc` contiene estado del
servidor excluyendo `.env`, claves y certificados; el checksum corresponde al
artefacto cifrado.

Restauración no destructiva:

```bash
./scripts/restore.sh backups/chat-backup-YYYYMMDDTHHMMSSZ.tar.gz.enc
find restore-* -maxdepth 3 -type f -print
```

El script solicita la misma passphrase (o usa `BACKUP_PASSPHRASE` en un job
controlado), verifica el checksum antes de descifrar, valida rutas contra
traversal y extrae a un directorio nuevo. Validar allí en un host/puerto
aislado. No reemplazar `data/` activo sin una ventana aprobada y un backup
actual. Aceptación: el proceso inicia, un usuario de prueba se autentica, el
flujo E2EE funciona y los logs no exponen contenido.

## 8. Actualizaciones

1. Crear copia/backup cifrado y registrar versión actual.
2. Revisar cambios de protocolo, migraciones y CVEs (`pip-audit`).
3. Probar en entorno aislado con datos sintéticos.
4. Desplegar, observar errores y healthcheck.
5. Tener rollback documentado, sin restaurar de manera ciega una DB vieja.

No cambiar algoritmos, formatos del sobre o parámetros de KDF sin versionar y
probar compatibilidad. Un cambio de clave pública requiere pinning/rotación
explícita, no reemplazo silencioso.

## 9. Respuesta rápida a incidentes

1. Asignar `incident_id`, registrar UTC y preservar logs sanitizados.
2. Revocar sesiones y aislar el backend si hay acceso no autorizado.
3. Deshabilitar cuentas/llaves comprometidas y notificar al responsable.
4. Rotar tokens/certificados/secretos solo después de conservar evidencia.
5. Verificar integridad de backups y restaurar en entorno limpio.
6. Comunicar alcance confirmado, acciones y limitaciones.
7. Cerrar con causa raíz y acciones de prevención.

Para una clave privada robada: revocar identidad, avisar a contactos, emitir
par nuevo y repetir verificación OOB. No prometer recuperación de mensajes
anteriores sin una capacidad criptográfica explícita.

## 10. Checklist de cierre

- [ ] `.env`, claves, certificados privados y DB no aparecen en `git status`.
- [ ] TLS valida SAN y cadena desde un cliente de prueba.
- [ ] Pruebas de autenticación, autorización, firmas, AEAD y replay pasan.
- [ ] Mensajes no aparecen en DB/logs/backend en texto legible.
- [ ] Backup cifrado y restore se ejecutaron en directorios aislados.
- [ ] Bandit/pip-audit/ZAP tienen reporte fechado o están declarados como
  pendientes sin inventar resultados.
- [ ] Se actualizó la matriz de `docs/INFORME.md` con evidencia real.
