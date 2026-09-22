# Informe del proyecto: mensajería instantánea cifrada

**Curso:** Ética y Seguridad de Datos (DS3031)
**Tipo de proyecto:** aplicación web con criptografía aplicada
**Versión:** 1.0 - documento de planificación, implementación y operación
**Fecha de corte:** 2026-09-18
**Equipo:** completar nombres y responsabilidades antes de la entrega

## Resumen ejecutivo

El proyecto resuelve un problema real: personas que necesitan intercambiar
mensajes privados a través de una infraestructura que no debe conocer el
contenido. La aplicación propone un cliente web y un backend de mensajería. El
cliente obtiene o verifica las claves públicas, cifra el contenido y recién
después lo entrega al servidor. El servidor autentica y autoriza la sesión,
transporta sobres cifrados, encola mensajes para usuarios desconectados y
registra eventos operativos mínimos sin guardar plaintext.

La protección se organiza en capas: AEAD para el mensaje (AES-256-GCM en el
cliente web; el prototipo de escritorio usaba ChaCha20-Poly1305), intercambio X25519 y
derivación HKDF-SHA256 para el secreto de sesión/mensaje, firma Ed25519 para
autenticidad del sobre, verificación de huellas fuera de banda para reducir el
riesgo de sustitución de claves, TLS con certificado emitido por una CA propia
para el transporte, hash de contraseñas, control de acceso, límites de tamaño y
frecuencia, auditoría sanitizada, backups y procedimientos de recuperación.

El diseño no afirma implementar Signal. No incluye Double Ratchet, prekeys,
servidor de claves de Signal ni anonimato de metadatos. Estas limitaciones son
parte explícita del análisis de riesgos y de las recomendaciones futuras.

### Limitaciones verificadas de esta versión

- Los tokens expiran y el login tiene rate limit en memoria, pero no hay
  revocación server-side ni un contador distribuido entre múltiples workers.
- El rate limit de mensajes y el backpressure para abuso volumétrico quedan
  pendientes; sí existen límites de tamaño y validación estructural.
- TLS se activa en el despliegue Compose mediante Uvicorn/OpenSSL. Un arranque
  local sin los parámetros `--ssl-*` sería HTTP y no debe exponerse.
- SQLite y el mapa de WebSockets son adecuados para un proceso académico; una
  operación multi-worker requiere broker/cola y almacenamiento compartido.
- La auditoría está en SQLite y aún requiere rotación/retención externa y
  almacenamiento inmutable para producción.
- Las claves privadas web son no extraíbles en IndexedDB, no un keystore de
  hardware; perder el perfil del navegador puede impedir descifrar mensajes.

## 1. Motivación y problema real

El uso cotidiano de chats deja mensajes en servidores, redes Wi-Fi, proxies,
backups y registros. Una cuenta comprometida, un administrador curioso o una
interceptación de red puede exponer conversaciones y credenciales. La solución
de este proyecto busca que el servidor pueda hacer entrega y control operativo
sin recibir el texto legible.

Los afectados son las personas que conversan, los operadores que administran
el servicio, la institución que custodia el repositorio y terceros mencionados
en los mensajes. Aunque el texto se cifra, el servidor puede observar
metadatos necesarios para enrutar: identificadores, momento aproximado,
tamaño, estado de entrega y, según el diseño de sesión, emisor y receptor.

### Pregunta de diseño

¿Cómo permitir una conversación usable y asíncrona, con front y back, cuando la
infraestructura de transporte no debe confiarse para la confidencialidad del
contenido?

### Alcance

- Registro e inicio de sesión con contraseñas almacenadas como hash de uso
  lento; sesiones firmadas con expiración y control de acceso. La revocación
  individual queda reconocida como mejora futura.
- Lista de contactos, publicación/consulta de claves públicas y verificación de
  huellas por un canal externo.
- Cifrado, firma, entrega, descifrado y visualización de mensajes.
- Entrega en tiempo real y cola para receptor desconectado, dentro de los
  límites de retención acordados.
- Frontend web práctico, backend, persistencia mínima y auditoría.
- TLS con certificado de desarrollo firmado por CA propia; en producción debe
  reemplazarse por una CA administrada o un certificado confiable.
- Documentación de riesgos, políticas, incidentes, backups y continuidad.

### Fuera de alcance

No se promete anonimato de tráfico, eliminación de metadatos, disponibilidad
24/7, recuperación de una clave privada perdida, protección de un endpoint con
malware, ni equivalencia con un mensajero maduro. Tampoco se guarda texto claro
para facilitar soporte; si el usuario pierde su clave privada, un backup de
mensajes cifrados no basta para descifrarlos.

## 2. Entregas y estado de requisitos

La siguiente matriz diferencia el punto de partida heredado del objetivo de la
versión web. ``Implementado`` significa que existe código y prueba de
aceptación; ``documentado`` significa que la medida está diseñada pero debe
comprobarse en la ejecución de la entrega; ``pendiente`` requiere trabajo
posterior y no debe presentarse como una capacidad disponible.

### 2.1 Requisitos funcionales

| ID | Requisito | Primera entrega (Tkinter/TCP) | Versión final web | Evidencia/aceptación |
|---|---|---|---|---|
| F-01 | Cliente y backend separados | Implementado | Implementado | Cliente carga y backend acepta sesión |
| F-02 | Registro/inicio de sesión | Pendiente | Implementado en `app/main.py` | Contraseña nunca aparece en logs; sesión válida |
| F-03 | Descubrimiento de usuarios | Implementado en línea | Implementado | Lista excluye datos no autorizados |
| F-04 | Distribución de claves públicas | Implementado sin identidad fuerte | Implementado con identidad autenticada | Huella estable y cambio bloqueado |
| F-05 | Redacción y envío de mensaje | Implementado | Implementado | Payload enviado es sobre cifrado |
| F-06 | Descifrado en receptor | Implementado | Implementado | Texto se muestra solo en cliente |
| F-07 | Tiempo real | Implementado mientras ambos están conectados | Implementado | WebSocket/stream o mecanismo equivalente |
| F-08 | Mensajes asíncronos | No implementado | Implementado con cola cifrada | Entrega *at-least-once*, ACK y deduplicación local por `msg_id` |
| F-09 | Verificación fuera de banda | Parcial: confirmación manual | Implementado | Huellas X25519/Ed25519 se comparan por canal externo |
| F-10 | Rechazo de replay | Implementado en memoria | Implementado con estado de entrega/ID único | Repetición no altera conversación |
| F-11 | Auditoría de operación | Solo consola | Implementado en tabla SQLite sanitizada | No contiene texto ni claves privadas |
| F-12 | Recuperación/backup | Pendiente | Scripts implementados; operación periódica pendiente | `scripts/backup.sh` y `scripts/restore.sh` probados de forma aislada |

### 2.2 Requisitos de seguridad

| ID | Requisito | Primera entrega | Versión final | Criterio de aceptación |
|---|---|---|---|---|
| S-01 | Confidencialidad en reposo del mensaje | Sobre cifrado, claves locales sin passphrase | Sobre cifrado; DB/backups protegidos por permisos y cifrado de volumen | No existe plaintext en `data/`, logs o backup |
| S-02 | Confidencialidad en transporte | TCP sin TLS | TLS con CA/certificado en Compose | Cliente rechaza certificado inválido |
| S-03 | Integridad y autenticidad | ChaCha20-Poly1305 + Ed25519 | AES-256-GCM + Ed25519, con versionado estricto del sobre | Modificación de ciphertext, campos firmados o firma falla |
| S-04 | Gestión de contraseñas | No existe | Hash Argon2id (o configuración documentada) y política de longitud | Test no recupera contraseña desde DB |
| S-05 | Acceso mínimo | Cualquier nombre podía registrarse | RBAC mínimo, propietario de claves y sesión | Usuario no lee/entrega mensajes ajenos |
| S-06 | Logs de auditoría | `print` con datos operativos | Eventos estructurados en SQLite; retención/rotación operativa pendiente | Logs no incluyen plaintext, secretos o tokens |
| S-07 | Validación y límites | Parcial | Esquemas, tamaño máximo, errores genéricos y rate limit de login; rate limit de mensajes pendiente | Inputs malformados no derriban el servicio |
| S-08 | Anti-replay | Set por sesión | ID único, expiración y estado de entrega persistente | Sobre repetido es descartado y auditado |
| S-09 | Protección de claves | Permisos 0600 | IndexedDB con claves no extraíbles; keystore OS y rotación futura | Claves privadas nunca se transmiten al backend |
| S-10 | Contingencia/DR | No existe | Scripts de backup cifrado y restauración no destructiva; scheduling pendiente | Restauración en entorno aislado es verificable |
| S-11 | Herramientas de análisis | No ejecutado | Bandit y pip-audit ejecutados; procedimiento ZAP documentado | Resultados y pendientes separados explícitamente |
| S-12 | Certificados digitales | No existe | CA propia para demo, SAN correcto y guía de renovación | `openssl verify` y conexión TLS exitosas |

Las etiquetas de la matriz deben actualizarse con evidencia del commit y prueba
antes de la presentación. Una propuesta documentada no equivale a una prueba
exitosa.

## 3. Arquitectura propuesta

```text
 Navegador A                           Navegador B
 (clave privada A)                     (clave privada B)
       |                                      |
       | HTTPS/WSS + TLS 1.2+ (preferir 1.3)   |
       +-------------------+------------------+
                           v
                 Backend de mensajería
             autenticación / autorización
             entrega / cola / límites de tamaño
             logs sin plaintext ni claves
                           |
                 DB: sobres cifrados
                 + auditoría sanitizada
```

El navegador cifra con la clave pública del destinatario y firma con su clave
de firma. El backend valida la sesión y el sobre estructuralmente, pero no
descifra el contenido. El canal TLS protege credenciales, huellas y sobres en
tránsito y reduce manipulación activa de la conexión; no reemplaza el cifrado
de extremo a extremo.

En la implementación web actual, `app.main:app` (FastAPI) sirve también el
contenido estático de `frontend/`. La API HTTP expone registro, login, perfil,
usuarios, claves públicas y auditoría; `/ws` recibe y entrega sobres. SQLite
persiste cuentas, claves públicas, sobres cifrados y eventos de auditoría, sin
columna de plaintext ni material privado. El navegador conserva claves no
extraíbles en IndexedDB. El despliegue Docker termina TLS en Uvicorn con el
certificado generado por la CA propia y mantiene el backend en el puerto 8443.
El WebSocket se autentica mediante su primer frame y no coloca el token en la
URL, evitando que la credencial aparezca en access logs o historial.

### Flujo de alta y contacto

1. El usuario crea cuenta con una contraseña y genera sus claves en el cliente.
2. La contraseña se envía solo por TLS al endpoint de autenticación; el backend
   guarda un hash lento, nunca la contraseña.
3. El cliente publica la parte pública y conserva las privadas localmente.
4. Antes del primer envío, se muestra la huella combinada de las claves y se
   confirma mediante llamada, presencialmente u otro canal independiente.
5. Un cambio posterior de clave bloquea el envío y genera alerta; no se acepta
   silenciosamente una nueva identidad.

### Flujo de mensaje

1. El emisor obtiene la clave pública fijada del destinatario.
2. Genera el material efímero, deriva una clave con X25519 + HKDF-SHA256,
   cifra con AES-256-GCM y firma los campos canónicos del sobre.
3. El backend valida autenticación, autorización, tamaño, versión, identidad de
   entrega e identificador único; persiste únicamente el sobre cifrado.
4. El receptor recibe el sobre por TLS, verifica la firma y el pinning, rechaza
   IDs ya procesados y descifra con su clave privada.
5. El texto se muestra en memoria. El cliente no lo envía a logs ni al backend.

## 4. Trasfondo teórico y decisiones criptográficas

### Confidencialidad e integridad

AES-256-GCM es un AEAD: cifra y autentica a la vez. Cada mensaje debe usar un
IV de 96 bits único para la clave derivada. El frontend web usa Web Crypto para
generarlo y el backend solo transporta ese valor. El AAD (si se incorpora a la
versión del formato) debe incluir al menos versión, emisor, receptor, timestamp
y `msg_id`; cambiar cualquiera de esos campos debe invalidar la etiqueta. El
prototipo de escritorio anterior usaba ChaCha20-Poly1305; sus sobres no son
interoperables con el formato web.

X25519 realiza un acuerdo de secreto sin transmitir la clave privada. HKDF con
SHA-256 convierte el secreto compartido en una clave de cifrado con contexto
(`info`) y salt aleatorio. Ed25519 firma la representación canónica del sobre,
lo que permite detectar modificaciones y ligar el mensaje a la identidad
publicada.

TLS protege el transporte, incluyendo autenticación de la sesión y
confidencialidad frente a observadores de red. Uvicorn/OpenSSL negocia la
versión disponible del runtime (TLS 1.2 o 1.3); se debe comprobar en la demo y
preferir TLS 1.3 cuando esté disponible. En desarrollo se usa una CA propia;
cada cliente debe confiar explícitamente en la CA del laboratorio y rechazar
otros certificados.

### Qué no cubre el diseño

La estrategia heredada de una clave efímera por mensaje no constituye Double
Ratchet. No hay prekeys ni rotación por cadena como en Signal. Si un atacante
obtiene una clave privada que aún permita descifrar sobres capturados, puede
existir riesgo para mensajes históricos. La recomendación es migrar a una
biblioteca/protocolo auditado antes de un uso de alta sensibilidad.

### Parámetros de configuración

| Elemento | Configuración | Motivo |
|---|---|---|
| Intercambio | X25519 | Curva moderna disponible en `cryptography` |
| Derivación web | HKDF-SHA256, 32 bytes, `clave-e2ee-v1` + identidad/ID | Separación de contexto |
| Cifrado web | AES-256-GCM, IV 12 bytes | AEAD disponible en Web Crypto |
| Cifrado legado | ChaCha20-Poly1305, nonce 12 bytes | Prototipo de escritorio; no mezclar formatos |
| Firma | Ed25519 | Firma corta y verificación eficiente |
| Huellas | SHA-256 de clave pública, representación hexadecimal | Comparación fuera de banda |
| Transporte | TLS 1.2+ (preferir 1.3), CA propia de laboratorio | Confidencialidad/autenticidad del canal |
| Password | Argon2id; parámetros en `.env` de despliegue | Resistencia a fuerza bruta |
| ID | UUID aleatorio por sobre | Deduplicación y anti-replay |

## 5. Protección de datos

### En reposo

- El texto de mensaje no se guarda como columna legible. La base contiene
  sobres y metadatos de entrega mínimos.
- El host debe cifrar el volumen de `data/`, `logs/` y `backups/` (FileVault,
  LUKS o volumen cifrado administrado). El archivo de configuración con
  secretos se inyecta por entorno/gestor de secretos, no desde Git.
- Los directorios de runtime usan permisos restrictivos. `scripts/backup.sh`
  fuerza `umask 077`, calcula SHA-256 y excluye claves privadas, `.env` y
  certificados.
- La clave privada de usuario se genera y conserva en el cliente. Una futura
  versión debe usar WebCrypto/Keychain/keystore y cifrado de exportación con
  clave derivada de la contraseña, con advertencia explícita sobre recuperación.

### En transporte

- Autenticación, claves públicas y sobres circulan por HTTPS/WSS con TLS.
- La CA de desarrollo se crea con `scripts/generate_certs.sh`; el certificado
  tiene SAN `localhost`, `127.0.0.1` y `::1`.
- No se deshabilita la verificación por aceptar cualquier certificado.
- HSTS, cookies `Secure`, `HttpOnly`, `SameSite` y una política CORS explícita
  son obligatorios para un despliegue accesible por red.

### Accesos y autorización

El backend debe distinguir usuario no autenticado, usuario autenticado y
operador. Cada operación consulta el propietario del recurso: leer/confirmar
una cola solo corresponde al receptor; enviar requiere una sesión válida y
contacto/clave aceptable; operar backups y logs requiere rol de operador. Los
mensajes de error no deben revelar si una cuenta existe. La versión actual
aplica expiración de tokens y limitación de intentos de login en memoria, pero la
revocación server-side, limitación de mensajes y bloqueo distribuido deben
completarse antes de un uso expuesto a Internet.

### Auditoría

La versión actual guarda en la tabla `audit_events` `timestamp`, actor,
operación, target y metadatos escalares. No se registran texto, contraseñas,
tokens, claves privadas, sobres completos ni cabeceras de autorización. La
retención propuesta es 30 días en desarrollo y 90 días en una operación
académica controlada, con acceso solo para el equipo autorizado; la rotación y
exportación externa siguen siendo tareas operativas pendientes. Los eventos se
deben revisar antes de exportarlos al informe.

## 6. Políticas, procedimientos y awareness

### Política de datos

Recolectar solo lo necesario para autenticar, enrutar, deduplicar y auditar.
Informar al usuario de los metadatos visibles por el servidor y del límite de
recuperación de una clave perdida. Borrar colas expiradas y atender una
solicitud de eliminación conforme a la política del curso, teniendo en cuenta
que backups pueden conservar una copia hasta su vencimiento.

### Procedimientos del equipo

- Revisar cambios de protocolo con dos personas.
- Mantener dependencias fijadas y revisar CVEs antes de cada entrega.
- No compartir claves privadas por chat, correo o issues.
- Usar cuentas de prueba y datos sintéticos en demos.
- Rotar certificados de laboratorio y revocar sesiones tras una sospecha.
- Ejecutar backup y prueba de restauración antes de una presentación.

### Concientización

Antes de usar el sistema, cada integrante debe identificar la huella de su
contacto por un canal independiente, reconocer una alerta de cambio de clave,
activar bloqueo de pantalla y reportar phishing/filtraciones. El equipo debe
practicar un incidente de credenciales expuestas y uno de pérdida de base de
datos, incluyendo quién decide aislar el servicio y quién comunica el evento.

## 7. Herramientas de análisis y resultados

El 18 de septiembre de 2026 se ejecutaron las comprobaciones locales indicadas
a continuación. Los resultados no equivalen a una auditoría independiente ni
permiten afirmar que el sistema carece de vulnerabilidades.

1. **Bandit:** `bandit -r app -x tests -ll` no reportó hallazgos de severidad
   media o alta.
2. **pip-audit:** la primera ejecución detectó `PYSEC-2026-1845` en la
   dependencia de desarrollo `pytest 8.4.2`. Se actualizó el requisito a
   `pytest>=9.0.3,<10`; la ejecución final reportó cero vulnerabilidades
   conocidas en `requirements.txt`.
3. **OWASP ZAP (pendiente):** proxy en un entorno de prueba contra el frontend y backend;
   revisar autenticación, cookies, CORS, XSS, CSRF, controles de acceso y
   headers. No ejecutar contra producción o datos reales.
4. **OpenSSL:** se generó una CA temporal, se validó la cadena con
   `openssl verify`, el SAN para `localhost` y una conexión HTTPS real a
   `/api/health` usando esa CA.
5. **Pruebas propias:** `pytest` finalizó con 7 pruebas aprobadas; también se
   verificaron sintaxis JavaScript/shell, backup cifrado y restauración no
   destructiva. Fuzzing, carga y DAST permanecen pendientes.

El reporte debe separar falsos positivos, hallazgos aceptados, mitigaciones y
riesgo residual. No se debe escribir "sin vulnerabilidades" solo porque una
herramienta no reportó hallazgos.

## 8. Riesgos y entidades afectadas

| Riesgo | Datos/activo | Afectados | Impacto | Mitigación |
|---|---|---|---|---|
| Clave privada del cliente robada | Identidad y mensajes futuros/históricos según esquema | Usuario y contactos | Descifrado/falsificación | Permisos, keystore, passphrase, revocación y rotación |
| MITM al publicar una clave | Claves públicas y sobres | Emisor/receptor | Confidencialidad e identidad | TLS + huella OOB + pinning + bloqueo de cambio |
| Cuenta comprometida | Sesión, cola y contactos | Usuario/contactos | Envíos no autorizados | MFA futura, expiración, revocación, rate limit |
| DB/backups filtrados | Sobres, IDs y metadatos | Todos los usuarios | Análisis de relaciones; contenido cifrado | Cifrado de volumen, ACL, retención y checksum |
| TLS mal configurado | Credenciales/sobres | Todos los clientes | Intercepción activa | CA/SAN, validación estricta y renovación |
| Replay o duplicación | `msg_id`, estados | Receptor | Confusión/acciones repetidas | Nonce/ID, deduplicación y expiración |
| XSS/CSRF en frontend | Mensajes en memoria/sesión | Usuario | Robo de sesión/contenido visible | CSP, escape, SameSite, CSRF y ZAP |
| Log excesivo | Texto, tokens, IP | Usuarios/equipo | Brecha secundaria | Esquema de auditoría, revisión y retención |
| Ransomware/pérdida | DB y código | Operador/usuarios | Indisponibilidad | Backups fuera del host, restauración y RTO |
| Dependencia vulnerable | Código/backend | Todos | Ejecución/DoS | pip-audit, pinning, actualización y aislamiento |

## 9. Plan de respuesta a incidentes

1. **Preparación:** contactos, acceso a logs, backups comprobados, inventario de
   certificados, cuentas de prueba y runbook en `docs/OPERATIONS.md`.
2. **Detección y triage:** asignar `incident_id`, conservar UTC, clasificar
   confidencialidad/integridad/disponibilidad y limitar el caso a evidencia
   sanitizada.
3. **Contención:** revocar sesiones/tokens, bloquear cuentas, aislar el
   servicio o limitarlo a mantenimiento, rotar credenciales/certificados
   comprometidos. No borrar logs ni el host antes de tomar copia forense.
4. **Erradicación:** corregir causa, parchear dependencias, eliminar persistencia
   maliciosa y comprobar que no hay claves expuestas.
5. **Recuperación:** restaurar en un entorno aislado, verificar checksums,
   aplicar migraciones, probar login/cifrado/entrega y reabrir gradualmente.
6. **Comunicación:** avisar al docente/equipo y a afectados según impacto;
   explicar qué datos, periodo y acciones sin especular.
7. **Lecciones:** informe post-incidente con línea de tiempo, causa raíz,
   controles fallidos, acciones, responsable y fecha de seguimiento.

Para pérdida o sospecha de clave privada, marcar la identidad como revocada,
notificar contactos, generar nuevas claves y repetir verificación OOB. Los
mensajes previos no se consideran recuperables por defecto.

## 10. Backups, DR, RPO y RTO

El objetivo académico es un **RPO de 24 horas** para el estado de entrega y un
**RTO de 4 horas** para recuperar el backend en un host limpio. Se mantienen al
menos tres copias: host activo, destino separado y copia offline/cifrada; una
prueba mensual verifica restauración. La clave privada de la CA no se incluye
en el backup automático: debe custodiarse por separado con control de acceso.

`scripts/backup.sh` crea un archivo `tar.gz.enc` cifrado con AES-256-CBC,
PBKDF2-SHA256 y salt aleatorio; excluye `.env`, certificados y claves, calcula
SHA-256 sobre el artefacto cifrado y aplica permisos 0600. La passphrase se
solicita de forma interactiva o se inyecta mediante `BACKUP_PASSPHRASE` desde un
gestor de secretos, nunca desde Git. Durante una restauración,
`scripts/restore.sh` valida checksum, descifra a un temporal, rechaza traversal
y enlaces antes de extraer a un directorio nuevo. El operador revisa el
contenido y lo promueve manualmente, de modo que un backup no sobrescribe
producción por accidente.

La recuperación se valida con: servicio inicia con un certificado válido,
usuarios de prueba pueden autenticarse, una conversación nueva se cifra y
descifra, un sobre antiguo no se duplica y los logs no revelan plaintext.

## 11. Recomendaciones futuras

- Migrar a un protocolo auditado con Double Ratchet, prekeys y gestión de
  dispositivos si el caso requiere confidencialidad futura y recuperación
  robusta. No diseñar una variante propia para producción.
- Integrar MFA/passkeys, recuperación con claves de respaldo y revocación de
  dispositivos.
- Usar WebCrypto/Keychain y cifrado de keystore con Argon2id, con UX clara para
  exportación y pérdida de clave.
- Añadir transparencia de claves (registro append-only firmado) para detectar
  sustitución masiva y rotación por dispositivo.
- Centralizar secretos, logs inmutables, alertas y gestión de certificados.
- Ejecutar revisión independiente, SAST/DAST, fuzzing de sobres y pruebas de
  carga antes de cualquier despliegue real.
- Evaluar minimización de metadatos, retención configurable y borrado seguro.
- Publicar una página de informe estático en GitHub Pages/Notion sin secretos ni
  datos de prueba identificables.

## 12. Pruebas y criterios de demostración

La demo debe cubrir, como mínimo:

- dos usuarios registran sesión y observan estados de conexión;
- huellas se comparan fuera de banda y un cambio de clave bloquea el envío;
- inspección de red/DB demuestra que el texto no aparece en el backend;
- una modificación de ciphertext, campo firmado, timestamp o firma impide descifrar;
- un `msg_id` repetido no se entrega dos veces;
- un receptor desconectado recibe la cola después de autenticarse;
- un usuario no autorizado no puede leer, borrar ni confirmar una cola ajena;
- TLS rechaza el certificado incorrecto y acepta solo la CA de laboratorio;
- `backup.sh` y `restore.sh` funcionan en un directorio nuevo;
- los logs muestran eventos útiles sin texto, contraseñas, tokens o claves.

Las pruebas de seguridad pueden ejecutarse solo con datos sintéticos. Los
resultados, fecha y versión deben agregarse como anexo cuando se ejecuten.

## 13. Lecciones aprendidas y retrospectiva

La primera versión permitió validar el núcleo criptográfico y la verificación
manual, pero evidenció que una buena primitiva no resuelve identidad,
disponibilidad, operación o UX. TCP sin TLS deja expuestas credenciales y
metadatos de sesión; almacenar claves sin protección de usuario complica la
seguridad en reposo; y una lista en memoria no ofrece entrega asíncrona ni
recuperación.

Para el siguiente ciclo el equipo debe acordar primero el modelo de amenaza,
el contrato versionado del sobre y los criterios de aceptación. Luego debe
implementar por verticales pequeñas: autenticación, un envío E2EE, persistencia
asíncrona, operación y finalmente hardening. La retrospectiva debe medir si
cada riesgo fue mitigado con una prueba, quién revisó el cambio y qué trabajo
se difiere. La principal mejora de coordinación es mantener un registro de
decisiones y no presentar una medida documentada como implementada sin
evidencia.

## Referencias técnicas

- RFC 7748, X25519 y X448.
- RFC 5869, HKDF.
- RFC 8439, ChaCha20-Poly1305.
- RFC 8032, Ed25519.
- RFC 8446, TLS 1.3.
- OWASP Application Security Verification Standard y OWASP ZAP.
- Documentación de `cryptography`, Bandit y pip-audit.

## Anexo A. Artefactos operativos

- [`THREAT_MODEL.md`](THREAT_MODEL.md): activos, límites de confianza, STRIDE y
  riesgos residuales.
- [`OPERATIONS.md`](OPERATIONS.md): configuración, certificados, despliegue,
  backup, restauración, monitoreo y respuesta.
- [`../scripts/generate_certs.sh`](../scripts/generate_certs.sh): CA y SAN local.
- [`../scripts/backup.sh`](../scripts/backup.sh) y
  [`../scripts/restore.sh`](../scripts/restore.sh): continuidad no destructiva.
- [`../SECURITY.md`](../SECURITY.md): reporte responsable y reglas de
  contribución.
