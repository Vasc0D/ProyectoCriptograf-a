# Modelo de amenazas

**Sistema:** mensajería instantánea cifrada (cliente web + backend)
**Método:** STRIDE sobre límites de confianza, complementado con riesgos de
disponibilidad, pérdida de claves y privacidad de metadatos.
**Suposición:** el servidor puede ser observado o comprometido; el endpoint del
usuario debe mantenerse bajo control del usuario.

## 1. Activos y clasificación

| Activo | Confidencialidad | Integridad | Disponibilidad |
|---|---|---|---|
| Texto de mensajes | Alta | Alta | Media |
| Claves privadas | Crítica | Crítica | Alta |
| Claves públicas/huellas | Media | Crítica | Media |
| Credenciales/sesiones | Crítica | Alta | Media |
| Sobres y cola | Alta por metadatos; payload cifrado | Alta | Alta |
| DB, logs y backups | Alta | Alta | Alta |
| Código y configuración TLS | Alta | Crítica | Alta |
| Metadatos de relación/tiempo | Media/Alta | Media | Media |

## 2. Actores

- **Usuario legítimo:** genera sus claves, cifra/descifra y verifica contactos.
- **Cliente malicioso:** controla su propio navegador e intenta abusar de la
  API, pero no debe leer recursos ajenos.
- **Atacante de red:** observa, modifica, repite o bloquea tráfico.
- **Servidor comprometido/administrador curioso:** lee lo que persiste y puede
  intentar sustituir claves públicas, pero no debe conocer plaintext si el
  endpoint está sano.
- **Operador:** mantiene certificados, logs y backups con privilegio mínimo.
- **Proveedor de almacenamiento:** puede ver blobs de backup si no se usa
  cifrado del volumen/destino.

## 3. Límites de confianza y flujo

```text
[Navegador A] --(clave pública del contacto)--> [Navegador A]
      |  plaintext solo en memoria / clave privada local
      | HTTPS/WSS TLS
      v
[Backend: auth, ACL, cola, límites]
      | sobre cifrado + metadatos mínimos
      v
[DB/logs/backups]
      ^
      | HTTPS/WSS TLS
[Navegador B: verifica firma, pinning, anti-replay, descifra]
```

El límite de confianza principal está entre navegador y backend. TLS protege el
canal, pero se debe asumir que un backend comprometido puede leer metadatos,
alterar la entrega o reemplazar material público. La huella comparada por un
canal independiente reduce, pero no elimina, ese riesgo.

## 4. Tabla STRIDE

| Amenaza | Escenario | Control preventivo | Detección/respuesta | Riesgo residual |
|---|---|---|---|---|
| Spoofing | Atacante registra el nombre de otra persona o roba una sesión | Auth, token aleatorio y expiración; revocación server-side pendiente | Auditoría de login, rotación manual y re-verificación de claves | MFA y revocación automática aún pendientes |
| Spoofing | Backend sustituye clave pública en primer contacto | TLS, pinning y huella fuera de banda | Alerta de cambio, bloqueo de envío | La primera verificación depende del usuario |
| Tampering | Se cambia ciphertext, destinatario, timestamp o campo firmado | AES-GCM + firma Ed25519 + validación canónica | Error de firma/tag, evento sanitizado | Denegación de servicio sigue siendo posible |
| Tampering | Replay de sobre válido | `msg_id` único, estado de entrega, ventana/expiración | Contador de replay y alerta | Persistencia y sincronización deben probarse |
| Repudiation | Usuario niega envío o operador modifica logs | Firma del sobre, `request_id`, logs append-only/retención | Correlación de eventos y revisión | Ed25519 prueba integridad, no identidad legal |
| Information disclosure | DB o backup filtrado contiene mensajes | Payload E2EE, cifrado de volumen/destino, permisos | Alertas de acceso, inventario, incidente | Metadatos y claves de endpoint pueden seguir expuestos |
| Information disclosure | Logs incluyen texto, tokens o claves | Esquema de auditoría allowlist, revisión y redacción | Escaneo de logs en CI, retención | Un nuevo módulo podría registrar de más |
| Denial of service | Flood de conexiones/mensajes o payload gigante | Límite de payload y rate limit de login; rate limit de mensajes/backpressure pendiente | Logs de error y reinicio controlado | DDoS volumétrico requiere infraestructura externa |
| Elevation of privilege | Usuario consulta cola o claves ajenas | ACL por propietario, validación server-side, roles | Tests 403 y auditoría | Fallos lógicos deben cubrirse con pruebas de autorización |
| Supply chain | Dependencia Python/frontend vulnerable | Dependencias fijadas, `pip-audit`, revisión | SCA en CI, parche/rollback | Vulnerabilidad 0-day puede no estar catalogada |
| Compromiso endpoint | Malware lee DOM, memoria o clave local | CSP, aislamiento, keystore, bloqueo de pantalla | Revocación y reemisión de claves | E2EE no protege un cliente ya comprometido |
| Pérdida | Fallo de disco/ransomware elimina DB | 3-2-1, backup, checksum, restore no destructivo | Prueba periódica de DR | RPO de 24 h: cambios recientes pueden perderse |

## 5. Casos de abuso prioritarios

### A1. Sustitución de clave pública

El atacante modifica la respuesta de `get_public_key`. Si el contacto ya está
fijado, el cliente debe bloquear. En el primer contacto, el usuario compara la
huella por una llamada o presencialmente. La interfaz nunca debe usar un simple
"continuar" sin mostrar la huella.

### A2. Robo de token de sesión

El atacante reutiliza un token Bearer obtenido mediante XSS o una máquina
compartida. La versión actual mantiene el token solo en memoria, aplica CSP y
valida firma y expiración en el backend. Cerrar sesión lo elimina del cliente,
pero no lo revoca en el servidor; una lista de revocación o sesiones opacas es
una mejora necesaria antes de exponer el sistema a Internet.

### A3. Entrega de un sobre a una cola ajena

Un usuario cambia `recipient_id` en una petición. El backend ignora confianza en
el cliente y deriva el propietario desde la sesión; si no coincide, devuelve
403 sin revelar existencia. El test debe intentar enviar, leer y borrar la cola
de otro usuario.

### A4. Replay y duplicación

Se captura un sobre válido y se reenvía. El receptor verifica `msg_id`,
timestamp/expiración y el estado persistente. El segundo intento se descarta,
no se muestra al usuario y queda un evento de auditoría sin contenido.

### A5. Pérdida de clave privada

El usuario borra su navegador o pierde dispositivo. El sistema no puede
descifrar retroactivamente con solo el backup de DB. Se informa esta limitación,
se permite revocar identidad y se genera un nuevo par, con verificación OOB de
contactos. La recuperación futura requiere un diseño de backup de claves con
consentimiento explícito.

## 6. Priorización

| Prioridad | Riesgos | Criterio |
|---|---|---|
| P0 | Claves privadas, bypass de ACL/auth, descifrado no autorizado | Bloquear entrega hasta corregir |
| P1 | TLS ausente, sustitución de claves, XSS/CSRF, logs con secretos | Corregir antes de demo externa |
| P2 | DoS básico, retención excesiva, restore no probado | Corregir antes de cierre del curso |
| P3 | Anonimato de metadatos, transparencia avanzada, UX de recuperación | Backlog futuro documentado |

## 7. Supuestos y preguntas abiertas

- Se asume que el usuario comprende la verificación de huellas y que el canal
  externo es auténtico.
- Se asume que el host de demo tiene su volumen cifrado y acceso restringido.
- Se debe confirmar si la rúbrica exige mensajes persistentes en la primera
  entrega o solo proponerlos.
- Se debe medir con pruebas la duración de retención y el RPO real antes de
  publicar cifras operativas.
- El uso de una biblioteca de protocolo auditada debe evaluarse antes de llamar
  al producto "seguro" en un contexto real.
