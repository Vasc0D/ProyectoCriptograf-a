# Política de seguridad

Esta política aplica al prototipo de mensajería instantánea cifrada de este
repositorio. El sistema es un proyecto académico y no debe usarse para
información cuya pérdida pueda causar daño real sin una revisión independiente,
pruebas de penetración y un proceso de operación formal.

## Alcance y modelo de datos

El cliente cifra el contenido antes de enviarlo. El backend solo necesita
transportar el sobre cifrado, identificadores de entrega y el mínimo de
metadatos de enrutamiento. Las claves privadas de los clientes son secretos y
no deben subirse al repositorio ni enviarse al servidor. Los registros no deben
contener plaintext, contraseñas, tokens, claves privadas ni sobres completos.

## Reportar una vulnerabilidad

No publiques una vulnerabilidad en un issue público. Envía un reporte privado
al responsable del curso o al mantenedor del repositorio con:

1. descripción y componente afectado;
2. pasos mínimos para reproducirla o un caso de prueba;
3. impacto, datos potencialmente expuestos y condiciones necesarias;
4. evidencia sanitizada, sin contraseñas, tokens, mensajes reales o claves.

Para incidentes activos, primero preservar evidencia y limitar la exposición
(revocar sesiones, aislar el servicio y conservar los logs) siguiendo
[`docs/OPERATIONS.md`](docs/OPERATIONS.md). No se deben probar cuentas o datos
de terceros sin autorización expresa.

## Priorización y respuesta

Se priorizan como críticas la exposición de claves privadas, descifrado no
autorizado, bypass de autenticación/autorización, falsificación de firmas o
alteración del protocolo. Se priorizan como altas la pérdida masiva de datos,
la ausencia de TLS o una inyección en el backend. El plan completo está en
[`docs/INFORME.md`](docs/INFORME.md) y [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Prácticas obligatorias para contribuciones

- No añadir secretos, `.env`, directorios `.keys/`, bases de datos, backups ni
  certificados privados al commit.
- Los backups operativos deben generarse con `scripts/backup.sh`: cifrado
  AES-256-CBC/PBKDF2 por defecto, passphrase fuera de Git y checksum del archivo
  cifrado. No tratar un `.tar.gz` sin cifrar como backup válido.
- Mantener validación estricta de entradas, límites de tamaño y rate limiting.
- No reemplazar primitivas criptográficas por algoritmos propios.
- Firmar/verificar el sobre en el cliente y usar AEAD con nonce único.
- Mantener TLS habilitado en despliegues distintos de pruebas locales.
- Ejecutar pruebas, Bandit y pip-audit antes de una entrega; si se incorpora
  frontend, ejecutar OWASP ZAP en un entorno aislado.
- Revisar cualquier cambio de protocolo con dos personas y documentar la
  migración/versionado.

## Divulgación y límites

El proyecto no promete disponibilidad, anonimato de metadatos ni protección
contra un endpoint comprometido. La política no autoriza pruebas ofensivas
contra el servidor ni contra servicios de terceros.
