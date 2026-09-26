# Clave Mensajería instantánea cifrada de extremo a extremo

**Curso:** Ética y Seguridad de Datos (DS3031)

**Integrantes:** Vasco Diaz Hurtado, Enzo Gomez Villegas y Bladimir Alferez

**Fecha:** 21 de septiembre de 2026

## Resumen ejecutivo

Clave es una aplicación web de mensajería instantánea que protege el contenido
de cada conversación mediante cifrado de extremo a extremo. El navegador del
emisor cifra y firma el mensaje antes de enviarlo. El servidor autentica a los
usuarios, conserva sobres cifrados y los entrega en tiempo real o cuando el
destinatario vuelve a conectarse, pero no recibe el texto legible ni las claves
privadas.

El proyecto parte de un prototipo de escritorio desarrollado en un curso de
criptografía. La nueva versión conserva ese aprendizaje y añade una interfaz
web, autenticación con contraseñas protegidas por Argon2id, persistencia en
SQLite, entrega asíncrona, verificación de identidad, comunicación HTTPS/WSS y
pruebas automatizadas. El resultado satisface los requisitos funcionales y de
seguridad definidos para una demostración académica, aunque no pretende
reemplazar protocolos maduros como Signal.

## 1 Motivación y alcance

Los servicios de mensajería convencionales necesitan almacenar o transportar
conversaciones a través de infraestructura que puede sufrir filtraciones,
errores de configuración o accesos indebidos. El problema abordado es cómo
permitir una conversación usable sin confiar al servidor la confidencialidad
del contenido. Por ello, la aplicación separa la función de entrega de la
función criptográfica: el servidor identifica destinatarios y administra la
cola, mientras que los navegadores cifran, verifican y descifran.

La solución contempla registro e inicio de sesión, descubrimiento de usuarios,
publicación de claves públicas, comparación de huellas, envío y recepción de
mensajes, almacenamiento de mensajes cifrados para usuarios desconectados y
confirmación de entrega. También incorpora una interfaz adaptable a distintos
tamaños de pantalla y mensajes comprensibles ante errores de autenticación,
conexión o verificación de identidad.

El alcance es académico. La aplicación no ofrece anonimato de metadatos,
protección frente a malware en el dispositivo, recuperación de claves privadas
perdidas ni secreto futuro mediante Double Ratchet. El servidor conoce los
usuarios que se comunican, el tamaño aproximado de los sobres y sus tiempos de
entrega. Estas limitaciones evitan presentar el prototipo como un producto de
seguridad listo para producción.

## 2 Planificación y ejecución

El trabajo se organizó a partir de una revisión del prototipo heredado. Esa
versión comprobaba el intercambio cifrado por TCP, pero no ofrecía una
experiencia web, autenticación de cuentas, almacenamiento persistente ni
entrega a usuarios desconectados. La planificación priorizó primero el recorrido
completo de un mensaje y después los controles que protegen cada etapa.

1. **Análisis y requisitos.** Se revisaron el cliente Tkinter, el servidor TCP y
   el formato criptográfico anterior. A partir de sus brechas se definieron las
   funciones, controles de seguridad y criterios de aceptación de la versión web.
2. **Diseño.** Se separaron las responsabilidades del navegador, la API, el
   WebSocket y la base de datos para que el servidor transportara sobres sin
   descifrar mensajes.
3. **Implementación.** Se desarrollaron el backend FastAPI, la interfaz web, el
   almacenamiento SQLite y la criptografía con Web Crypto hasta completar el
   flujo de registro, contacto, cifrado, entrega y confirmación.
4. **Validación.** Se ejecutaron pruebas del backend, revisiones de sintaxis y
   comprobaciones de seguridad. El resultado fue un recorrido de demostración
   reproducible con siete pruebas automatizadas aprobadas.

Durante la ejecución se hicieron tres ajustes relevantes. Primero, la
autenticación del WebSocket pasó al primer mensaje de la conexión para evitar
que el token apareciera en la URL o en registros de acceso. Segundo, las claves
privadas se cifran con AES-256-GCM antes de guardarse en IndexedDB; la clave de
protección se deriva de la contraseña con PBKDF2-SHA-256 y 310 000 iteraciones.
Al iniciar sesión se descifran en memoria y se importan como objetos `CryptoKey`
no extraíbles. Este diseño evita depender de que el navegador pueda persistir
directamente objetos criptográficos no extraíbles y mantiene el material
privado cifrado en reposo. Tercero, el cliente valida que las claves privadas
recuperadas correspondan a las claves públicas registradas. Los ajustes
surgieron al revisar el flujo completo y no solo el algoritmo de cifrado.

## 3 Trasfondo teórico

El cifrado de extremo a extremo significa que el contenido se transforma en el
dispositivo emisor y solo puede recuperarse en el dispositivo receptor. TLS
protege la conexión con el servidor, pero no sustituye esta propiedad: sin
cifrado de extremo a extremo, el servidor todavía podría leer los mensajes.

La implementación usa X25519 para acordar un secreto a partir de una clave
privada local y una clave pública del destinatario. HKDF con SHA-256 transforma
ese secreto y un valor aleatorio en una clave de 256 bits con contexto propio
para cada mensaje. AES-256-GCM cifra el texto y genera una etiqueta de
autenticación que permite detectar modificaciones. Ed25519 firma una
representación canónica del sobre para comprobar quién lo creó y proteger sus
campos principales.

Cada usuario publica únicamente sus claves públicas. Las claves privadas se
generan en el navegador y no se transmiten al backend. La aplicación calcula
una huella SHA-256 para que dos personas puedan compararla mediante otro canal.
La primera clave aceptada queda fijada con un esquema de confianza en el primer
uso. Si cambia posteriormente, el cliente bloquea el envío hasta que el usuario
vuelva a verificarla.

| Componente | Elección | Propósito |
|---|---|---|
| Acuerdo de claves | X25519 | Obtener un secreto compartido sin transmitir claves privadas |
| Derivación | HKDF con SHA-256 | Producir una clave diferente y contextualizada por mensaje |
| Cifrado autenticado | AES-256-GCM | Proteger confidencialidad e integridad del texto |
| Firma digital | Ed25519 | Autenticar el sobre y detectar alteraciones |
| Contraseñas | Argon2id | Reducir el impacto de una filtración de hashes |

## 4 Requisitos funcionales y de seguridad

Los requisitos funcionales describen las acciones que debe completar una
persona. Los requisitos de seguridad establecen las condiciones bajo las que
esas acciones pueden considerarse protegidas.

### 4.1 Requisitos funcionales

| ID | Requisito | Cumplimiento |
|---|---|---|
| F1 | Registrar una cuenta e iniciar sesión | Implementado mediante API y sesión firmada con expiración |
| F2 | Consultar usuarios disponibles | Implementado sin exponer contraseñas ni claves privadas |
| F3 | Publicar y consultar claves públicas | Implementado con claves X25519 y Ed25519 |
| F4 | Verificar la identidad de un contacto | Implementado mediante huellas y confirmación fuera de banda |
| F5 | Enviar y recibir mensajes en tiempo real | Implementado mediante WebSocket autenticado |
| F6 | Recibir mensajes enviados durante una desconexión | Implementado con cola cifrada persistente |
| F7 | Confirmar la entrega y evitar duplicados | Implementado con identificadores únicos y ACK |
| F8 | Utilizar la aplicación desde escritorio o móvil | Implementado con una interfaz web adaptable |

### 4.2 Requisitos de seguridad

| ID | Requisito | Cumplimiento |
|---|---|---|
| S1 | El servidor no debe recibir mensajes en texto claro | El cifrado y descifrado ocurren en el navegador |
| S2 | Las claves privadas no deben salir del dispositivo | Se guardan cifradas en IndexedDB y se importan como `CryptoKey` no extraíbles solo en memoria |
| S3 | La modificación de un sobre debe detectarse | AES-GCM y Ed25519 validan contenido y campos firmados |
| S4 | La sustitución de una clave debe ser visible | La huella queda fijada y un cambio bloquea el envío |
| S5 | Las contraseñas no deben almacenarse directamente | El backend guarda hashes Argon2id |
| S6 | Un usuario no debe enviar en nombre de otro | El backend contrasta la sesión con el remitente del sobre |
| S7 | Un mismo mensaje no debe procesarse repetidamente | Los identificadores se deduplican y persisten |
| S8 | Credenciales y metadatos deben viajar por un canal seguro | El despliegue admite HTTPS/WSS con certificado TLS |
| S9 | Entradas inválidas o excesivas deben rechazarse | Existen validación estructural, límites de tamaño y rate limit de login |

## 5 Diseño de la solución

La arquitectura tiene tres componentes. El frontend se ejecuta en el navegador
y concentra la interfaz, las claves privadas y las operaciones criptográficas.
El backend FastAPI registra cuentas, verifica sesiones, publica claves públicas
y administra conexiones WebSocket. SQLite almacena usuarios, claves públicas,
sobres cifrados, estados de entrega y eventos de auditoría sin contenido
legible.

La experiencia de uso sigue el recorrido habitual de una aplicación de chat.
Después de iniciar sesión, el usuario ve sus contactos, selecciona uno y puede
consultar su huella. La caja de texto se habilita cuando existe una identidad
local válida y la clave del contacto está verificada. Los estados de conexión,
entrega, error o cambio de identidad se muestran dentro de la interfaz para que
la seguridad no dependa de mensajes de consola.

### 5.1 Flujo de registro y contacto

1. El navegador genera los pares X25519 y Ed25519.
2. La persona registra su cuenta a través de TLS.
3. El backend almacena el hash Argon2id y las claves públicas.
4. El cliente cifra las claves privadas con una clave derivada de la contraseña y guarda el paquete cifrado en IndexedDB.
5. Al iniciar sesión, el cliente descifra el paquete en memoria y reimporta las claves como no extraíbles.
6. Antes de conversar, los usuarios comparan sus huellas por un canal distinto.

### 5.2 Flujo de un mensaje

1. El emisor obtiene la clave pública fijada del destinatario.
2. El navegador genera una clave X25519 efímera y deriva una clave con HKDF.
3. El texto se cifra con AES-256-GCM y el sobre se firma con Ed25519.
4. El sobre viaja por WSS. El backend valida sesión, remitente, destinatario,
   versión, tamaño e identificador, y lo conserva cifrado hasta entregarlo.
5. El receptor verifica la firma y la huella, descarta repeticiones y descifra
   localmente. Después envía una confirmación para actualizar el estado.

Este flujo aplica defensa en profundidad. El cifrado de extremo a extremo
protege el contenido frente al servidor; TLS protege la sesión y los metadatos
en tránsito; la firma protege la autoría del sobre; y la verificación manual
reduce el riesgo de que el servidor sustituya silenciosamente una clave.

## 6 Implementación y validación

El backend utiliza Python, FastAPI, Uvicorn y SQLite. La autenticación y las
sesiones se implementan en `app/auth.py`; los modelos de persistencia se
encuentran en `app/db.py`; y la API, validaciones y WebSocket se coordinan desde
`app/main.py`. El frontend usa HTML, CSS y JavaScript sin frameworks externos.
La criptografía se ejecuta con Web Crypto y el estado local se conserva en
IndexedDB. Las claves privadas quedan cifradas con AES-256-GCM y una clave
derivada de la contraseña mediante PBKDF2-SHA-256; solo se descifran en memoria
durante la sesión.

El repositorio incluye configuración para ejecutar el servicio directamente o
en Docker. El contenedor usa un usuario sin privilegios y un sistema de archivos
de solo lectura, salvo los directorios destinados a datos y registros. Los
certificados de laboratorio se generan con una autoridad certificadora local.
Estas medidas apoyan la demostración, pero el núcleo evaluado es el flujo
funcional y criptográfico de la aplicación.

La validación automatizada cubre registro, login, limitación de intentos,
rechazo de suplantación, validación del formato del sobre, cola para usuarios
desconectados y confirmación de entrega. La ejecución final produjo siete
pruebas aprobadas. También se comprobó la sintaxis del JavaScript y de los
scripts de operación. Las verificaciones de dependencias y análisis estático no
reportaron vulnerabilidades conocidas ni hallazgos de severidad media o alta en
la versión entregada.

La principal limitación criptográfica es la ausencia de Double Ratchet y
prekeys. La aplicación tampoco recupera una identidad si se pierde el perfil
del navegador y no oculta metadatos de comunicación. Para un despliegue real se
recomienda adoptar un protocolo auditado, incorporar revocación de sesiones y
usar almacenamiento y colas preparados para múltiples procesos.

## 7 Lecciones aprendidas y retrospectiva del equipo

El primer aprendizaje fue que usar algoritmos correctos no basta para construir
un sistema seguro. El prototipo anterior cifraba mensajes, pero la nueva versión
obligó al equipo a tratar autenticación, identidad, persistencia, estados de
entrega y errores de interfaz como partes del mismo diseño. Revisar el recorrido
completo permitió detectar riesgos que no aparecían al observar únicamente la
función de cifrado.

El segundo aprendizaje fue separar las capacidades implementadas de las
propuestas futuras. Durante el trabajo se documentaron límites concretos, como
la falta de Double Ratchet, revocación individual y recuperación de claves. Esta
distinción mejora la comunicación ética del proyecto porque evita atribuir al
prototipo garantías que todavía no ofrece.

Como equipo, podemos mejorar la coordinación mediante responsables explícitos
por cada requisito, revisiones cruzadas y criterios de aceptación acordados
antes de programar. En un siguiente proyecto registraríamos las decisiones de
arquitectura desde el inicio y desarrollaríamos en entregas verticales pequeñas:
autenticación, primer mensaje cifrado, persistencia, experiencia de usuario y
endurecimiento. Cada etapa terminaría con una demostración y una prueba asociada
al riesgo que busca reducir.

## Referencias

RFC 7748 para X25519; RFC 5869 para HKDF; RFC 8032 para Ed25519; NIST SP
800-38D para GCM; RFC 8446 para TLS 1.3; OWASP Application Security
Verification Standard; y documentación de Web Crypto, FastAPI, Argon2 y
`cryptography`.
