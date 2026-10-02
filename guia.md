# Guía completa de IntegriDos (PAI1-ST5)

Esta guía explica **qué hace cada parte del código** y **cómo usar el proyecto para todo**: arrancarlo, usar el cliente, lanzar los ataques, grabar las capturas, pasar los tests, inspeccionar la base de datos y resolver los problemas típicos.

El README es la versión corta. Esta es la larga.

---

## Índice

1. [La idea en dos minutos](#1-la-idea-en-dos-minutos)
2. [Requisitos e instalación](#2-requisitos-e-instalación)
3. [Mapa de carpetas](#3-mapa-de-carpetas)
4. [Uso básico: servidor y cliente](#4-uso-básico-servidor-y-cliente)
5. [El protocolo, mensaje a mensaje](#5-el-protocolo-mensaje-a-mensaje)
6. [El código, función por función](#6-el-código-función-por-función)
7. [Ataques de demostración](#7-ataques-de-demostración)
8. [Capturas de tráfico (.pcap)](#8-capturas-de-tráfico-pcap)
9. [Tests](#9-tests)
10. [La base de datos por dentro](#10-la-base-de-datos-por-dentro)
11. [Ajustes y parámetros](#11-ajustes-y-parámetros)
12. [Problemas frecuentes](#12-problemas-frecuentes)
13. [Decisiones de seguridad y limitaciones conocidas](#13-decisiones-de-seguridad-y-limitaciones-conocidas)
14. [Glosario](#14-glosario)

---

## 1. La idea en dos minutos

Un cliente manda órdenes de transferencia a un servidor de banco por **TCP sin cifrar**. El enunciado prohíbe TLS, así que cualquiera que esté en medio puede leer y modificar los mensajes. Lo que no puede hacer es **modificarlos sin que se note**.

- **Firma de cada mensaje.** Cada mensaje lleva una firma **HMAC-SHA256** que depende de todo su contenido y de una **clave secreta** que solo tienen el cliente y el servidor. Si alguien cambia un solo carácter, la firma deja de cuadrar y el servidor rechaza el mensaje.
- **Ningún mensaje vale dos veces.** Cada mensaje lleva un **nonce** (un número aleatorio que no se repite nunca) y un **timestamp** (la hora a la que se creó). El servidor apunta los nonces que ya ha visto y rechaza los mensajes demasiado viejos. Así, reenviar un mensaje capturado (**replay**) no sirve.
- **La clave secreta no viaja nunca por la red.** Sale de la contraseña del usuario con **PBKDF2**, y el login se hace por **reto-respuesta**: el cliente demuestra que conoce la contraseña sin enviarla.
- **Las firmas se comparan en tiempo constante** con `hmac.compare_digest`. Así, un atacante no puede ir adivinando la firma midiendo cuánto tarda el servidor en responder (**timing attack**).
- **La propia base de datos está protegida.** Cada fila lleva su propia firma, hecha con una clave que el servidor guarda aparte. Si alguien edita el `.db` a mano, se detecta.

Todo está hecho con la **librería estándar de Python**, sin instalar nada.

---

## 2. Requisitos e instalación

| Qué | Detalle |
|---|---|
| Python | 3.10 o superior (se usa la sintaxis `dict \| None`) |
| Sistema | Linux, macOS o Windows 10/11 |
| Dependencias | Ninguna, basta con la librería estándar |
| Para las capturas | Wireshark (en Windows con Npcap) o `tcpdump` en Linux |

Para conseguir el código:

```bash
git clone https://github.com/tomgutgar/pai1-st5.git
cd pai1-st5
python --version        # debe decir 3.10 o más
```

> **Windows:** si `python` abre la Microsoft Store o no existe, usa `py`. Por ejemplo, `py -m servidor.main`.

> **Muy importante:** todos los comandos se lanzan **desde la carpeta raíz del repo** y con `python -m carpeta.fichero`, sin `.py` y con punto en vez de barra. Así Python encuentra los módulos `comun`, `cliente` y `servidor`. Si lanzas `python servidor/main.py`, falla con `ModuleNotFoundError`.

---

## 3. Mapa de carpetas

La estructura sigue la **Figura 2 del enunciado** (cliente → canal → servidor con capa de validación y capa de negocio → bases de datos).

```
pai1-st5/
├── comun/
│   └── protocolo.py       Lo que comparten cliente y servidor: tramas, HMAC, PBKDF2
├── cliente/
│   ├── interfaz.py        Menú en consola (lo que ve el usuario)
│   ├── generador.py       Construye y firma los mensajes
│   └── conexion.py        Socket TCP: enviar y recibir tramas
├── servidor/
│   ├── main.py            Arranca el servidor
│   ├── conexion.py        Un hilo por cliente: lee tramas y responde
│   ├── validacion.py      Capa de validación de seguridad (MAC, timestamp, nonce)
│   ├── negocio.py         Capa de negocio (registro, login, transferencias)
│   └── datos.py           SQLite + sesiones en memoria + firmas de filas
├── ataques/
│   ├── mitm_proxy.py      Man-in-the-Middle (activo o pasivo)
│   ├── replay.py          Reenvía una trama capturada
│   └── timing.py          Mide == frente a compare_digest
├── tests/
│   ├── test_protocolo.py  Tests de las funciones del protocolo
│   └── test_seguridad.py  Tests contra un servidor real (un test por ataque)
├── evidencias/
│   ├── pcap/              Aquí van los .pcap
│   └── logs/              servidor.log y capturadas.jsonl
├── docs/                  Memoria
├── planteamiento.md       Diseño inicial
├── guia.md                Esta guía
└── README.md              Manual rápido
```

Ficheros que se generan solos y **no se suben al repo** (están en `.gitignore`):

| Fichero | Qué es |
|---|---|
| `secbank.db` | Base de datos SQLite del servidor |
| `servidor.key` | Clave de 256 bits del servidor para firmar las filas de la BD |
| `__pycache__/` | Caché de Python |

---

## 4. Uso básico: servidor y cliente

### 4.1 Arrancar el servidor

```bash
python -m servidor.main                    # escucha en 127.0.0.1:5000
python -m servidor.main 127.0.0.1 6000     # otro puerto
python -m servidor.main 0.0.0.0 5000       # accesible desde otros ordenadores de la red
```

Al arrancar, el servidor hace esto:
1. Crea `evidencias/logs/` si no existe y empieza a escribir en `evidencias/logs/servidor.log` y por pantalla.
2. Abre `secbank.db`, o lo crea con sus tablas si no existe.
3. Lee `servidor.key`. Si no existe, genera una clave aleatoria de 32 bytes y la guarda.
4. Crea los usuarios de prueba que falten.
5. **Revisa la integridad de toda la BD**: si alguna fila ha sido modificada a mano, lo apunta como `ERROR` en el log.
6. Se queda escuchando. Se para con **Ctrl+C**.

Así se ve el log:

```
2026-09-22 11:40:30,390 INFO    conexión de 127.0.0.1:36370
2026-09-22 11:40:30,658 INFO    login OK bob
2026-09-22 11:40:30,658 WARNING 127.0.0.1:36370 RECHAZADO: MAC inválido: el mensaje ha sido alterado
```

### 4.2 Arrancar el cliente

En **otra terminal**, también desde la raíz:

```bash
python -m cliente.interfaz                    # se conecta a 127.0.0.1:5000
python -m cliente.interfaz 127.0.0.1 5001     # a través del proxy MitM
python -m cliente.interfaz 192.168.1.20 5000  # a un servidor en otro ordenador
```

Si el servidor no está arrancado, verás `No se pudo conectar con ... ¿Está el servidor arrancado?`.

### 4.3 El menú

Sin sesión:
```
================================================
              SecBank · IntegriDos
 Sesión: sin iniciar
================================================
 1) Registrarse
 2) Iniciar sesión
 0) Salir
```

Con sesión:
```
 1) Nueva transferencia
 2) Cerrar sesión
 0) Salir
```

Se escribe el número y se pulsa Enter. Después de cada acción aparece *"Pulsa Enter para continuar..."* para que dé tiempo a leer el resultado.

### 4.4 Usuarios de prueba

| Usuario | Contraseña |
|---|---|
| alice | alice1234 |
| bob | bob12345 |
| carol | carol1234 |

### 4.5 Registrarse

Opción **1** sin sesión. Pide usuario, contraseña y la contraseña otra vez. Las contraseñas no se ven al escribirlas.

| Regla | Error si no se cumple |
|---|---|
| Usuario solo con letras y números, 32 como máximo | `usuario no válido (solo letras y números, máximo 32)` |
| Contraseña de 8 caracteres o más | `la contraseña debe tener al menos 8 caracteres` |
| Usuario nuevo | `el usuario ya existe` |
| Las dos contraseñas iguales | `Las contraseñas no coinciden` (lo comprueba el propio cliente) |

### 4.6 Iniciar sesión

Opción **2** sin sesión.

- **Usuario:** se pide una sola vez.
- **Contraseña incorrecta:** la vuelve a pedir en el mismo sitio, **hasta 5 intentos**.
- **Volver al menú:** deja la contraseña **vacía** y pulsa Enter. No gasta intento.
- **Bloqueo:** al **5º fallo seguido**, el servidor bloquea la cuenta **5 minutos**. Si lo intentas mientras tanto, verás `usuario bloqueado 287 s por demasiados intentos`.
- **Usuario que no existe:** el mensaje es el mismo que con una contraseña mala (`credenciales incorrectas`), para no revelar qué usuarios existen.

### 4.7 Hacer una transferencia

Opción **1** con sesión.

```
 Cuenta origen  (ES + 22 dígitos): ES1234567890123456789012
 Cuenta destino (ES + 22 dígitos): ES9876543210987654321098
 Importe en EUR: 1500,50
```

- **Importe:** se puede escribir con coma o con punto. Se redondea a 2 decimales.
- **Letras del IBAN:** se pasan a mayúsculas solas.
- **Si todo va bien:** sale `[OK] Transferencia registrada` y el `id` (un UUIDv4).

Qué comprueba el servidor:

| Comprobación | Error |
|---|---|
| IBAN = 2 letras + 22 dígitos | `origin_account no es un IBAN válido ...` |
| Origen distinto de destino | `la cuenta de origen y la de destino son la misma` |
| 0 < importe ≤ 1.000.000, con 2 decimales como máximo | `importe no válido ...` |
| Moneda EUR | `solo se admite EUR` |
| `tx_id` no usado antes | `tx_id repetido` |

### 4.8 Cerrar sesión y salir

- **Opción 2 con sesión:** cierra la sesión. El servidor la borra y la clave de sesión deja de servir.
- **Opción 0:** sale. Si había una sesión abierta, antes manda el logout.
- **Ctrl+C:** también sale.

---

## 5. El protocolo, mensaje a mensaje

### 5.1 Formato de trama

- **Mensaje:** cada mensaje es **un objeto JSON en una sola línea, terminado en `\n`**, en UTF-8. Es la "Opción A" del enunciado.
- **Tamaño máximo:** 64 KiB por línea. Si una línea es más larga, se descarta.

### 5.2 Conversación completa

```
 CLIENTE                                                     SERVIDOR
    │                                                            │
    │  LOGIN_INIT {username}                                     │
    │ ─────────────────────────────────────────────────────────► │ genera server_nonce (16 bytes)
    │  {salt, server_nonce}                                      │ y lo guarda como "reto" de esta conexión
    │ ◄───────────────────────────────────────────────────────── │
    │                                                            │
    │  K = PBKDF2(password, salt)       ← el servidor tiene la misma K guardada
    │  client_nonce = 16 bytes aleatorios                        │
    │  proof = HMAC(K, server_nonce ‖ client_nonce)              │
    │                                                            │
    │  LOGIN {username, client_nonce, proof}                     │
    │ ─────────────────────────────────────────────────────────► │ compara proof en tiempo constante
    │                                                            │ clave_sesion = HMAC(K, "session"‖sn‖cn)
    │  {session_id}  + nonce, timestamp, hmac                    │
    │ ◄───────────────────────────────────────────────────────── │ respuesta FIRMADA con clave_sesion
    │                                                            │
    │  clave_sesion = HMAC(K, "session"‖sn‖cn)  ← la misma, calculada en local
    │                                                            │
    │  TRANSFER {session_id, payload} + nonce, timestamp, hmac   │
    │ ─────────────────────────────────────────────────────────► │ 1. ¿sesión válida?
    │                                                            │ 2. ¿HMAC correcto?
    │                                                            │ 3. ¿timestamp dentro de ±120 s?
    │                                                            │ 4. ¿nonce nuevo?
    │  {tx_id} + nonce, timestamp, hmac                          │ 5. valida datos y guarda
    │ ◄───────────────────────────────────────────────────────── │
    │                                                            │
    │  LOGOUT {session_id} + nonce, timestamp, hmac              │
    │ ─────────────────────────────────────────────────────────► │ borra la sesión
```

### 5.3 Ejemplos reales de tramas

**Registro.** Es el único mensaje con la contraseña en claro:
```json
{"action": "REGISTER", "username": "dave", "password": "dave12345"}
{"status": "OK"}
```

**Reto de login:**
```json
{"action": "LOGIN_INIT", "username": "alice"}
{"status": "OK", "salt": "9f2c…(32 hex)", "server_nonce": "a41b…(32 hex)"}
```

**Respuesta al reto.** La contraseña no aparece por ningún sitio:
```json
{"action": "LOGIN", "username": "alice", "client_nonce": "07de…", "proof": "5c1a…(64 hex)"}
{"status": "OK", "session_id": "e3f0…(64 hex)", "nonce": "…", "timestamp": 1790070015, "hmac": "…"}
```

**Transferencia firmada:**
```json
{"action": "TRANSFER",
 "session_id": "e3f0…",
 "payload": {"tx_id": "caaa4fb9-c117-41cb-9d4d-ecdb4e0f5931",
             "origin_account": "ES1234567890123456789012",
             "destination_account": "ES9876543210987654321098",
             "amount": 200.0, "currency": "EUR"},
 "nonce": "7da3172a40c73eb9db764ff256ab1952",
 "timestamp": 1790070015,
 "hmac": "1039902a9df5938d445e255413c7b397818ced1fa0b13b226ffbd66e0da13b72"}
```

**Error.** Los errores van sin firmar:
```json
{"status": "ERROR", "reason": "MAC inválido: el mensaje ha sido alterado"}
```

### 5.4 ¿Qué bytes exactos se firman?

El HMAC no se calcula sobre el texto tal como viaja, sino sobre su **forma canónica**:
- todos los campos **menos `hmac`**,
- con las claves **ordenadas alfabéticamente** (también dentro de `payload`),
- **sin espacios** (`separators=(",", ":")`).

Así da igual en qué orden lleguen los campos o cómo se formatee el JSON: cliente y servidor firman exactamente los mismos bytes. Como el `nonce` y el `timestamp` están dentro de lo firmado, **no se pueden cambiar sin romper la firma**.

### 5.5 ¿Por qué los errores no van firmados?

Muchos errores ocurren **antes** de saber qué clave usar: sesión inexistente, trama rota, login fallido. Para no complicar el protocolo, la regla es simple: **el cliente solo se fía de un `OK` que llegue con firma válida**.

Un atacante podría inventarse un `ERROR`, pero eso solo molesta al usuario (una denegación de servicio). Nunca puede fabricar un `OK` falso.

---

## 6. El código, función por función

### 6.1 `comun/protocolo.py`: el protocolo compartido

| Constante | Valor | Para qué |
|---|---|---|
| `PBKDF2_ITERS` | 600 000 | Iteraciones de PBKDF2 (recomendación de OWASP). Más iteraciones, más lento y más caro para un atacante que pruebe contraseñas |
| `TIME_WINDOW` | 120 | Segundos de diferencia máxima entre el timestamp del mensaje y la hora del servidor |
| `MAX_FRAME` | 65 536 | Tamaño máximo de una línea, para que nadie agote la memoria del servidor |

**`derive_key(password, salt) -> bytes`**
Aplica `hashlib.pbkdf2_hmac("sha256", password, salt, 600000)` y devuelve 32 bytes (256 bits). La usan el servidor al **registrar** un usuario y el cliente al hacer **login**, y los dos obtienen la misma `K`. Tarda unas décimas de segundo a propósito.

**`mac(key, data) -> bytes`**
HMAC-SHA256 en crudo: `hmac.new(key, data, hashlib.sha256).digest()`. Devuelve 32 bytes. Es la pieza base de todo: firmas de mensajes, prueba de login, clave de sesión y firmas de filas de la BD.

**`canonical(msg) -> bytes`**
Convierte un mensaje en los bytes que se firman (ver 5.4): quita `hmac`, ordena las claves y quita los espacios.

**`sign(msg, key) -> dict`**
Devuelve una **copia** del mensaje con tres campos más:
- `nonce`: 16 bytes aleatorios de `secrets.token_hex(16)`, en hexadecimal.
- `timestamp`: `int(time.time())`.
- `hmac`: `mac(key, canonical(msg))` en hexadecimal (64 caracteres).

**`verify_mac(msg, key) -> bool`**
Recalcula el HMAC del mensaje recibido y lo compara con el campo `hmac` usando **`hmac.compare_digest`**, que tarda lo mismo acierte o falle (RS4). Si el campo `hmac` falta o es de un tipo raro, devuelve `False` sin lanzar excepción.

**`send_frame(sock, msg)`**
`json.dumps(msg)` + `\n`, enviado con `sendall`, que se asegura de mandarlo entero.

**`recv_frame(rfile) -> dict | None`**
Lee una línea del socket.
- Devuelve `None` si el otro lado cerró la conexión (línea vacía).
- Lanza `ValueError` si la línea supera `MAX_FRAME`, si no es JSON o si es un JSON que no es un objeto (una lista o un texto, por ejemplo).

### 6.2 `servidor/datos.py`: persistencia

Guarda todo lo del servidor:
- **SQLite:** las tablas `users`, `nonces` y `transactions`.
- **Memoria:** las sesiones, en un diccionario (`_sesiones`).
- **Fichero aparte:** la clave del servidor (`clave_servidor`), leída de `servidor.key`.

| Elemento | Qué es |
|---|---|
| `SESSION_TTL = 1800` | Una sesión caduca a los 30 minutos |
| `ESQUEMA` | El SQL que crea las 3 tablas (ver sección 10) |
| `_db` | La conexión SQLite, compartida por todos los hilos |
| `_lock` | Candado para que dos hilos no toquen la BD a la vez |
| `_sesiones` | `{session_id: (usuario, clave_sesion, caduca_en)}` |
| `clave_servidor` | 32 bytes leídos de `servidor.key` |

**`init(ruta_db, ruta_clave)`**
Si `servidor.key` no existe, lo crea con 32 bytes aleatorios y permisos `600` (solo lo lee su dueño; en Windows no tiene efecto). Después carga la clave, abre la BD y crea las tablas que falten. Se llama una sola vez, al arrancar el servidor o los tests.

**`_uno(sql, *args)` y `_todos(sql, *args)`**
Ayudantes internos que ejecutan una consulta con el candado cogido.
- `_uno` devuelve una fila y hace **commit** al terminar (o rollback si falla).
- `_todos` devuelve todas las filas.

**`firma_fila(*campos) -> str`**
Pasa los campos a una lista JSON (los `bytes` se pasan a hexadecimal antes) y devuelve `HMAC(clave_servidor, esa_lista)` en hexadecimal. Es el `row_mac` que protege cada fila.

**`fila_integra(row_mac, *campos) -> bool`**
Recalcula la firma de la fila y la compara con `row_mac` en tiempo constante.

**`crear_usuario(usuario, salt, clave) -> bool`**
Inserta el usuario con su `row_mac`. Devuelve `False` si ya existía: la `PRIMARY KEY` de `username` lanza `IntegrityError`. Así se impiden los duplicados (RF1c) directamente en la BD, sin carreras entre hilos.

**`leer_usuario(usuario)`**
Devuelve `(salt, clave, bloqueado_hasta, fila_integra)`, o `None` si el usuario no existe. El último valor dice si su `row_mac` cuadra.

**`apuntar_fallo(usuario, max_fallos, bloqueo_seg)`**
Suma 1 a `failed`. Si llega a `max_fallos`, pone `failed = 0` y `locked_until = ahora + bloqueo_seg`. Se hace con dos `UPDATE` en SQL para que el contador sea correcto aunque haya varios intentos a la vez.

**`limpiar_fallos(usuario)`**
Pone `failed = 0`. Se llama tras un login correcto, porque el bloqueo es por fallos **seguidos**.

**`registrar_nonce(nonce) -> bool`**
Es el corazón del anti-replay (RS3b):
1. Borra los nonces vistos hace más de `2 × TIME_WINDOW` (240 s). Ya no hace falta recordarlos: un mensaje tan viejo lo rechazaría el control de timestamp.
2. Intenta insertar el nonce. Si ya existía, la `PRIMARY KEY` falla y devuelve `False`, que significa **replay**.

Las dos cosas pasan dentro de la misma transacción, con el candado cogido.

**`guardar_transaccion(tx_id, origen, destino, importe, moneda, ts, usuario) -> bool`**
Inserta la transferencia con su `row_mac`. Pasa el importe a `float` para que `100` y `100.0` firmen igual (SQLite siempre lo devuelve como `100.0`). Devuelve `False` si el `tx_id` ya existía.

**`filas_corruptas() -> list[str]`**
Recorre `users` y `transactions` y devuelve las filas cuyo `row_mac` no cuadra, por ejemplo `["transactions/caaa4fb9-…"]`. El servidor la llama al arrancar.

**`crear_sesion(usuario, clave_sesion) -> str`**
Genera un `session_id` de 64 caracteres hexadecimales (`secrets.token_hex(32)`) y lo guarda en memoria con su caducidad.

**`leer_sesion(sid)`**
Devuelve `(usuario, clave_sesion)`, o `None` si no existe o ha caducado. Si había caducado, la borra.

**`borrar_sesion(sid)`**
Elimina la sesión (logout). Si no existía, no hace nada.

### 6.3 `servidor/validacion.py`: capa de validación de seguridad

**`class Rechazado(Exception)`**
Excepción para cualquier rechazo previsto. Su texto es lo que ve el cliente en `reason` y lo que queda en el log como `RECHAZADO: ...`.

**`comprobar_prueba_login(clave, server_nonce, client_nonce, prueba) -> bool`**
Calcula `HMAC(K, server_nonce ‖ client_nonce)` y lo compara con la `proof` que mandó el cliente, **en tiempo constante**.

**`verificar_mensaje(msg) -> (usuario, clave_sesion)`**
El filtro por el que pasa todo mensaje que va dentro de una sesión (`TRANSFER` y `LOGOUT`). Hace las comprobaciones en este orden y lanza `Rechazado` en la primera que falle:

| # | Comprobación | Error |
|---|---|---|
| 1 | La sesión existe y no ha caducado | `sesión no válida o caducada` |
| 2 | El HMAC es correcto | `MAC inválido: el mensaje ha sido alterado` |
| 3 | `|ahora − timestamp| ≤ 120 s` | `timestamp fuera de la ventana permitida` |
| 4 | El nonce no se había visto | `nonce repetido: posible ataque de replay` |

**¿Por qué el MAC va antes que el nonce?** Si el nonce se guardara antes de comprobar la firma, un atacante sin la clave podría llenar la tabla de nonces con basura, o "gastar" por adelantado nonces que luego usaría el cliente legítimo.

### 6.4 `servidor/negocio.py`: capa de lógica de negocio

| Constante | Valor | Para qué |
|---|---|---|
| `MAX_FALLOS` | 5 | Fallos de login seguidos antes de bloquear |
| `BLOQUEO_SEG` | 300 | Segundos que dura el bloqueo |
| `USUARIOS_PRUEBA` | alice, bob, carol | Usuarios iniciales (RF1b) |
| `IBAN` | `[A-Z]{2}\d{22}` | Formato de cuenta aceptado |

**`atender(msg, estado) -> (respuesta, clave | None)`**
El "repartidor". Mira `msg["action"]` y llama a la función que toca. Devuelve la respuesta y la clave con la que hay que firmarla (`None` significa sin firmar). `estado` es un diccionario propio de cada conexión, donde se guarda el reto de login pendiente. `LOGOUT` se resuelve aquí mismo: verifica el mensaje y borra la sesión.

**`registrar(usuario, password)`**
Valida el formato de usuario y contraseña, genera un **salt aleatorio de 16 bytes** (`secrets.token_bytes`), calcula `K = derive_key(password, salt)` y guarda `(usuario, salt, K)`. La contraseña **no se guarda nunca**. Lanza `Rechazado` si algo falla o si el usuario ya existe.

**`sembrar()`**
Crea los usuarios de `USUARIOS_PRUEBA` que no existan. Se llama al arrancar.

**`login_init(usuario, estado) -> dict`**
Devuelve el `salt` del usuario y un `server_nonce` nuevo, y guarda `(usuario, server_nonce)` en `estado["reto"]`. **Si el usuario no existe**, se inventa un salt con `HMAC(clave_servidor, usuario)[:16]`, que siempre es el mismo para ese nombre. Así, desde fuera no se distingue un usuario real de uno inventado.

**`login(msg, estado) -> (respuesta, clave_sesion)`**
1. Saca el reto de `estado`. Un reto sirve para **un solo intento**, así que se borra al usarlo. Si no hay reto, o es de otro usuario: `hay que pedir LOGIN_INIT antes de LOGIN`.
2. Lee el usuario de la BD. Si no existe: `credenciales incorrectas`.
3. Si su `row_mac` no cuadra: `error de integridad en la cuenta`, y se apunta un `ERROR` en el log.
4. Si está bloqueado: `usuario bloqueado N s por demasiados intentos`.
5. Comprueba la `proof`. Si falla, llama a `apuntar_fallo` y responde `credenciales incorrectas`.
6. Si todo va bien, llama a `limpiar_fallos`, calcula `clave_sesion = HMAC(K, "session" ‖ sn ‖ cn)`, crea la sesión y devuelve el `session_id` firmado con esa clave.

**`validar_transaccion(p)`**
Comprueba el `payload`: `tx_id` UUIDv4, los dos IBAN con formato válido y distintos entre sí, un importe numérico (no booleano) entre 0 y 1.000.000 con 2 decimales como máximo, y moneda `EUR`. Lanza `Rechazado` con un mensaje claro.

**`transferir(msg) -> (respuesta, clave_sesion)`**
`verificar_mensaje`, después `validar_transaccion` y después `guardar_transaccion`. Lo apunta en el log (`TRANSFER OK alice …`) y devuelve el `tx_id` firmado.

### 6.5 `servidor/conexion.py`: lector de buffer

**`class Manejador(socketserver.StreamRequestHandler)`**
`socketserver` crea un objeto de esta clase, en **un hilo propio**, por cada cliente que se conecta.

**`Manejador.handle()`**
Repite hasta que el cliente cierra:
1. `recv_frame` lee una línea.
2. `atender` la procesa.
3. Envía la respuesta, **firmada** si `atender` devolvió una clave.

Cómo gestiona los errores:
- `Rechazado` → responde `ERROR` con el motivo y lo apunta en el log como `WARNING`.
- `ValueError`, `KeyError`, `TypeError` o `AttributeError` (JSON roto, campos que faltan, tipos raros) → responde `trama mal formada` **y sigue atendiendo**. Una trama basura no tumba el servidor ni corta la conexión.
- `ConnectionError` (el cliente se fue de golpe) → termina sin ruido.

### 6.6 `servidor/main.py`: arranque

**`main()`**
Lee `host` y `puerto` de la línea de comandos, configura el log (fichero + pantalla), llama a `datos.init`, a `negocio.sembrar` y a `datos.filas_corruptas`, y arranca un `ThreadingTCPServer`.
- **Reutilizar el puerto:** en Linux se activa `allow_reuse_address` para poder reiniciar el servidor enseguida. En Windows no, porque allí esa opción permite que otro programa "robe" el puerto.
- **Hilos:** `daemon_threads = True` hace que los hilos de clientes no impidan cerrar el programa.

### 6.7 `cliente/conexion.py`: interfaz de conexión

**`class Conexion`**

| Método | Qué hace |
|---|---|
| `__init__(host, puerto)` | Abre el socket TCP (timeout de 10 s) y un lector de líneas sobre él |
| `pedir(msg) -> dict` | Envía un mensaje y espera la respuesta. Lanza `ConnectionError` si el servidor cierra |
| `cerrar()` | Cierra el socket |

### 6.8 `cliente/generador.py`: generador de mensajes asegurado

| Función | Devuelve | Notas |
|---|---|---|
| `registro(usuario, password)` | mensaje `REGISTER` | Único mensaje con la contraseña en claro |
| `login_init(usuario)` | mensaje `LOGIN_INIT` | |
| `login(usuario, password, salt_hex, server_nonce_hex)` | `(mensaje LOGIN, clave_sesion)` | Calcula `K`, genera `client_nonce`, calcula `proof` y la clave de sesión |
| `transferencia(sid, clave, origen, destino, importe)` | mensaje `TRANSFER` firmado | Genera el `tx_id` con `uuid.uuid4()` |
| `logout(sid, clave)` | mensaje `LOGOUT` firmado | |

### 6.9 `cliente/interfaz.py`: la interfaz de usuario

| Elemento | Qué hace |
|---|---|
| `ANCHO = 48` | Ancho de la cabecera |
| `INTENTOS_LOGIN = 5` | Intentos de contraseña antes de volver al menú |
| `pantalla(usuario)` | Limpia la consola (`cls` en Windows, `clear` en el resto) y pinta la cabecera |
| `respuesta_ok(resp, clave=None)` | `True` solo si `status == "OK"` **y**, cuando hay clave, la firma de la respuesta es válida. Si no, imprime `[ERROR] motivo` o `[ALERTA] ... posible manipulación` |
| `registrarse(con)` | Pide los datos, comprueba que las contraseñas coinciden y manda `REGISTER` |
| `iniciar_sesion(con)` | Bucle de hasta 5 intentos. Cada intento pide un reto nuevo (`LOGIN_INIT`) y manda `LOGIN`. Para si acierta, si la contraseña está vacía o si el error no es de contraseña (por ejemplo, un bloqueo). Devuelve `(usuario, session_id, clave_sesion)` o `None` |
| `transferir(con, sid, clave)` | Pide cuentas e importe, manda `TRANSFER` y comprueba que la respuesta firmada trae **el mismo `tx_id`** que se envió |
| `main()` | Conecta, muestra el menú en bucle y gestiona Ctrl+C y la pérdida de conexión |

### 6.10 `ataques/`

**`mitm_proxy.py`**

| Elemento | Qué hace |
|---|---|
| `ESCUCHA`, `SERVIDOR` | Dónde escucha el proxy (5001) y a dónde reenvía (5000) |
| `PASIVO` | `True` si se lanzó con `--pasivo` |
| `CUENTA_ATACANTE` | IBAN al que el atacante desvía el dinero |
| `alterar(linea)` | Si la línea es un `TRANSFER`: en modo **activo** multiplica el importe por 100 y cambia el destino, dejando el `hmac` intacto porque no puede recalcularlo sin la clave; en modo **pasivo** no toca nada y copia la línea en `evidencias/logs/capturadas.jsonl` |
| `tubo(origen, destino, cambiar)` | Copia líneas de un socket a otro pasándolas por `cambiar`. Si un lado se cierra, cierra los dos |
| `main()` | Acepta clientes y lanza dos tubos por cliente: cliente→servidor (con `alterar`) y servidor→cliente (sin tocar) |

**`replay.py` → `main()`**
Coge la **última línea** del fichero de capturas y la manda tal cual, byte a byte, por una conexión nueva. Imprime la respuesta del servidor.

**`timing.py`**

| Elemento | Qué hace |
|---|---|
| `LONGITUD` | Tamaño del "secreto" de prueba (100 000 bytes, para que la diferencia se vea por encima del ruido) |
| `medir(funcion, candidato)` | Microsegundos por comparación. Se queda con el mínimo de 7 tandas de 2 000 repeticiones, que es la medida menos afectada por el ruido |
| `main()` | Para 0, 10, 25, 50, 75, 90 y 100 % de bytes acertados, mide `==` y `compare_digest`, imprime la tabla y la guarda en `evidencias/timing.csv` |

---

## 7. Ataques de demostración

> Todas las demos necesitan el **servidor arrancado** (`python -m servidor.main`) en su propia terminal.

### 7.1 Man-in-the-Middle (alteración del mensaje)

```bash
# terminal 2
python -m ataques.mitm_proxy
# terminal 3
python -m cliente.interfaz 127.0.0.1 5001
```

En el cliente: login (por ejemplo, `bob` / `bob12345`) y una transferencia de 200 €.

Lo que verás:

| Dónde | Mensaje |
|---|---|
| Proxy | `[MitM] 200.0 EUR a ES98…  ==>  20000.0 EUR a ES6600000000000000000666` |
| Cliente | `[ERROR] MAC inválido: el mensaje ha sido alterado` |
| Log del servidor | `WARNING … RECHAZADO: MAC inválido: el mensaje ha sido alterado` |

La transferencia **no** se guarda en la BD.

> El login sí funciona a través del proxy activo porque el proxy solo toca los `TRANSFER`.

### 7.2 Replay (reenvío de un mensaje legítimo)

```bash
# terminal 2: el atacante escucha sin tocar nada
python -m ataques.mitm_proxy --pasivo
# terminal 3: el usuario trabaja con normalidad a través del proxy
python -m cliente.interfaz 127.0.0.1 5001
#   → login + una transferencia (llega bien: [OK])
#   → NO cierres la sesión
# terminal 4: el atacante reenvía lo capturado
python -m ataques.replay
```

El resultado depende del tiempo que pase entre la transferencia y el reenvío:

| Cuándo reenvías | Respuesta | Qué lo para |
|---|---|---|
| Antes de 120 s | `nonce repetido: posible ataque de replay` | Tabla de nonces |
| Después de 120 s | `timestamp fuera de la ventana permitida` | Timestamp |
| Tras cerrar sesión | `sesión no válida o caducada` | Sesión borrada |

Para la memoria conviene enseñar los dos primeros casos.

Opciones de `replay.py`:
```bash
python -m ataques.replay                                   # última línea de evidencias/logs/capturadas.jsonl
python -m ataques.replay mi_captura.jsonl                  # otro fichero
python -m ataques.replay mi_captura.jsonl 192.168.1.20 5000
```

> **Truco:** también puedes copiar una trama desde Wireshark (*Seguir secuencia TCP*), pegarla como una línea en un `.txt` y pasárselo a `replay.py`.

### 7.3 Canal lateral de tiempo

```bash
python -m ataques.timing
```

```
 % acertado |   == (µs) |  compare_digest (µs)
         0% |     0.050 |               64.192
        10% |     0.192 |               64.479
        50% |     1.139 |               64.870
       100% |     2.816 |               64.601
```

- **`==`:** tarda más cuantos más bytes acierta, porque para en el primer byte distinto. Un atacante que mida tiempos podría ir adivinando la firma byte a byte.
- **`compare_digest`:** tarda lo mismo siempre, así que no da ninguna pista.

Los datos quedan en `evidencias/timing.csv`. Se abre con Excel o LibreOffice y se hace un gráfico de líneas con el porcentaje de bytes acertados en el eje X y las dos columnas de tiempo.

Los números cambian de un ordenador a otro. Lo importante es la **forma**: una línea sube y la otra se queda plana.

---

## 8. Capturas de tráfico (.pcap)

Son un **entregable obligatorio**. Conviene hacer una por escenario:

| Fichero | Escenario |
|---|---|
| `evidencias/pcap/normal.pcap` | Registro, login, transferencia correcta y logout |
| `evidencias/pcap/mitm.pcap` | Demo 7.1 |
| `evidencias/pcap/replay.pcap` | Demo 7.2 |

### Linux

```bash
sudo tcpdump -i lo -w evidencias/pcap/normal.pcap 'tcp port 5000 or tcp port 5001'
# …haz la demo… y para con Ctrl+C
```

### Windows

1. Instala Wireshark marcando **Npcap** y la opción *Support loopback traffic*.
2. Abre Wireshark y elige la interfaz **Adapter for loopback traffic capture**.
3. Pulsa el botón de captura (la aleta azul), haz la demo y pulsa el cuadrado rojo.
4. *Archivo → Guardar como…* → `evidencias/pcap/normal.pcap`.

### Analizarlas en Wireshark

- **Filtro de visualización:** `tcp.port == 5000 || tcp.port == 5001`.
- **Ver la conversación completa:** clic derecho sobre un paquete → **Seguir → Secuencia TCP**. En rojo sale lo que envía el cliente y en azul lo que responde el servidor.
- **En la captura MitM** hay dos conversaciones:
  - cliente ↔ proxy (puerto 5001), con el importe original;
  - proxy ↔ servidor (puerto 5000), con el importe cambiado **y el mismo `hmac`**.

  Ponerlas una al lado de la otra es la mejor prueba para la memoria.
- **En la captura de replay:** el mismo `nonce` aparece dos veces, la segunda con la respuesta `nonce repetido`.
- **Qué comentar en la memoria**, no basta con pegar la imagen:
  - la contraseña **no aparece** en el login (solo en el registro);
  - cada mensaje lleva `nonce`, `timestamp` y `hmac`;
  - por qué se rechaza cada ataque.

---

## 9. Tests

```bash
python -m unittest discover tests -v                     # todos (unos 7 s)
python -m unittest tests.test_protocolo -v               # solo los del protocolo
python -m unittest tests.test_seguridad.TestSeguridad.test_replay_nonce_repetido   # uno solo
```

Para guardar la salida como evidencia:
```bash
python -m unittest discover tests -v 2> evidencias/logs/tests.txt
```

`unittest` escribe en stderr, de ahí el `2>`.

### `tests/test_protocolo.py`

Prueba las funciones del protocolo sin red.

| Test | Qué comprueba |
|---|---|
| `test_canonica_no_depende_del_orden` | El mismo JSON con los campos en otro orden da los mismos bytes |
| `test_canonica_ignora_el_campo_hmac` | El campo `hmac` no entra en lo que se firma |
| `test_firma_valida` | Un mensaje firmado verifica y su HMAC mide 64 hex (256 bits) |
| `test_firma_valida_tras_viajar_como_json` | Sigue verificando después de pasar a JSON y volver |
| `test_mensaje_alterado_no_verifica` | Si se cambia el importe, la firma deja de valer |
| `test_nonce_o_timestamp_alterados_no_verifican` | No se puede "refrescar" un mensaje viejo cambiando nonce o timestamp |
| `test_clave_distinta_no_verifica` | Con otra clave no verifica |
| `test_hmac_ausente_o_raro_no_verifica` | `None`, vacío, caracteres no ASCII, números o listas → `False`, sin excepción |
| `test_nonces_distintos` | Cada firma lleva un nonce nuevo |
| `test_derivacion_con_salt` | PBKDF2 da 32 bytes, es determinista y con otro salt da otra clave |
| `test_tramas_mal_formadas` | Texto, lista, cadena o una línea gigante → `ValueError` |
| `test_conexion_cerrada` | Una línea vacía → `None` |

### `tests/test_seguridad.py`

Arranca un **servidor de verdad** en un puerto libre, con una BD temporal, y habla con él por TCP.

| Test | Requisito | Qué comprueba |
|---|---|---|
| `test_registro_y_duplicado` | RF1a, RF1c | Registrar funciona y repetir el usuario da `ya existe` |
| `test_password_guardada_con_salt_y_no_en_claro` | RS1a | Cada usuario tiene un salt distinto y la contraseña no está en la BD |
| `test_login_correcto_con_respuesta_firmada` | RF1, RS2 | Login OK, con la respuesta firmada |
| `test_login_mal_y_usuario_inexistente` | RS1 | Mismo error con contraseña mala que con usuario inexistente |
| `test_bloqueo_tras_5_fallos` | RS1b | Tras 5 fallos, ni la contraseña buena entra |
| `test_login_sin_reto` | Protocolo | Un `LOGIN` sin `LOGIN_INIT` previo se rechaza |
| `test_transferencia_correcta` | RF2 | Transferencia OK, con respuesta firmada y el mismo `tx_id` |
| `test_mitm_importe_alterado` | RS2 | Importe cambiado → `MAC inválido` |
| `test_mitm_mac_falsificado` | RS2 | Firmado con otra clave → `MAC inválido` |
| `test_transaccion_con_datos_invalidos` | RF2 | IBAN corto, importe negativo, 3 decimales u origen igual a destino → `ERROR` |
| `test_replay_nonce_repetido` | RS3 | El mismo mensaje dos veces → `nonce repetido` |
| `test_replay_timestamp_caducado` | RS3 | Un mensaje bien firmado pero de hace 5 min → `timestamp` |
| `test_logout_invalida_la_sesion` | RF1d | Después del logout, la sesión ya no sirve |
| `test_sesion_inventada` | RF1d | Un `session_id` inventado → `sesión no válida` |
| `test_trama_mal_formada_no_tumba_el_servidor` | Robustez | Cuatro tramas basura → `ERROR`, y la conexión sigue viva |
| `test_manipular_la_bd_se_detecta` | Política | Cambiar un importe en el `.db` → `filas_corruptas()` lo detecta |

---

## 10. La base de datos por dentro

### Tablas

```sql
users(username PK, salt, key, row_mac, failed, locked_until)
nonces(nonce PK, seen_at)
transactions(tx_id PK, origin, dest, amount, currency, ts, username, row_mac)
```

| Columna | Qué es |
|---|---|
| `users.salt` | 16 bytes aleatorios, distintos para cada usuario |
| `users.key` | `PBKDF2(password, salt)`, 32 bytes. **No es la contraseña** |
| `users.row_mac` | Firma de `(username, salt, key)` con la clave del servidor |
| `users.failed` / `locked_until` | Fallos seguidos y hasta cuándo está bloqueado (hora Unix) |
| `nonces.seen_at` | Cuándo se vio el nonce. Los de más de 240 s se borran solos |
| `transactions.ts` | Timestamp del mensaje con el que llegó la transferencia |
| `transactions.row_mac` | Firma de toda la fila con la clave del servidor |

Las sesiones **no están en la BD**: viven en la memoria del servidor.

### Mirar la BD

Con Python, que funciona en cualquier sistema:
```bash
python -c "import sqlite3; [print(f) for f in sqlite3.connect('secbank.db').execute('SELECT tx_id, origin, dest, amount, username FROM transactions')]"
python -c "import sqlite3; [print(f) for f in sqlite3.connect('secbank.db').execute('SELECT username, hex(salt), failed, locked_until FROM users')]"
```

Con la herramienta `sqlite3`, si la tienes instalada:
```bash
sqlite3 secbank.db "SELECT * FROM transactions;"
```

### Demostrar que se detecta una manipulación de la BD

1. Haz alguna transferencia y **para el servidor**.
2. Cambia un importe a mano:
   ```bash
   python -c "import sqlite3; c=sqlite3.connect('secbank.db'); c.execute('UPDATE transactions SET amount = 999999'); c.commit()"
   ```
3. Arranca el servidor otra vez. En el log verás una línea como esta por cada fila tocada:
   ```
   ERROR   INTEGRIDAD BD: la fila transactions/caaa4fb9-… ha sido manipulada
   ```

Con `users` pasa lo mismo: si alguien cambia la `key` de un usuario, ese usuario ya no puede entrar y sale `error de integridad en la cuenta`.

### Desbloquear un usuario sin esperar 5 minutos

```bash
python -c "import sqlite3; c=sqlite3.connect('secbank.db'); c.execute(\"UPDATE users SET locked_until=0, failed=0 WHERE username='alice'\"); c.commit()"
```

`locked_until` y `failed` no entran en el `row_mac`, así que esto no dispara la alarma de integridad.

### Empezar de cero

Para el servidor y borra `secbank.db`. Al volver a arrancar se recrean las tablas y los usuarios de prueba.

> **Ojo:** si borras `servidor.key` pero **no** `secbank.db`, se genera una clave nueva y **todas las filas antiguas parecen manipuladas**, porque se firmaron con la clave vieja. Borra siempre los dos juntos.

---

## 11. Ajustes y parámetros

Todo está en constantes al principio de cada fichero:

| Qué | Dónde | Valor por defecto |
|---|---|---|
| Iteraciones de PBKDF2 | `comun/protocolo.py` → `PBKDF2_ITERS` | 600 000 |
| Ventana de tiempo anti-replay | `comun/protocolo.py` → `TIME_WINDOW` | 120 s |
| Tamaño máximo de trama | `comun/protocolo.py` → `MAX_FRAME` | 64 KiB |
| Duración de una sesión | `servidor/datos.py` → `SESSION_TTL` | 1800 s |
| Fallos antes de bloquear | `servidor/negocio.py` → `MAX_FALLOS` | 5 |
| Duración del bloqueo | `servidor/negocio.py` → `BLOQUEO_SEG` | 300 s |
| Usuarios de prueba | `servidor/negocio.py` → `USUARIOS_PRUEBA` | alice, bob, carol |
| Intentos de login en la UI | `cliente/interfaz.py` → `INTENTOS_LOGIN` | 5 |
| Puertos del proxy | `ataques/mitm_proxy.py` → `ESCUCHA`, `SERVIDOR` | 5001 → 5000 |

> Si cambias `PBKDF2_ITERS` con usuarios ya creados, esos usuarios dejan de poder entrar: su `K` se calculó con otras iteraciones. Borra `secbank.db` y `servidor.key` después de cambiarlo.

### Usarlo entre dos ordenadores

1. En el ordenador del servidor: `python -m servidor.main 0.0.0.0 5000`.
2. Averigua su IP: `ip a` en Linux, `ipconfig` en Windows.
3. En Windows, deja pasar el puerto 5000 en el firewall. Suele salir un aviso la primera vez; acepta en "Redes privadas".
4. En el otro ordenador: `python -m cliente.interfaz <IP_DEL_SERVIDOR> 5000`.

Para las capturas, graba en la interfaz de red real (`eth0`, `wlan0` o `Wi-Fi`), no en loopback. El proxy MitM escucha en `127.0.0.1`: para ponerlo entre dos máquinas, cambia `ESCUCHA` a `("0.0.0.0", 5001)` y `SERVIDOR` a la IP del servidor.

---

## 12. Problemas frecuentes

| Síntoma | Causa | Solución |
|---|---|---|
| `ModuleNotFoundError: No module named 'comun'` | Lo lanzaste como `python servidor/main.py` o desde otra carpeta | Desde la raíz del repo: `python -m servidor.main` |
| `No se pudo conectar con 127.0.0.1:5000` | El servidor no está arrancado o usa otro puerto | Arráncalo, o pasa al cliente el puerto correcto |
| `WinError 10061` / `Connection refused` | Lo mismo | Lo mismo |
| `Address already in use` / `WinError 10048` | Ya hay un servidor o un proxy en ese puerto | Ciérralo, o usa otro puerto |
| `timestamp fuera de la ventana permitida` en una transferencia normal | Los relojes del cliente y del servidor se llevan más de 2 minutos (pasa entre dos máquinas) | Sincroniza la hora en los dos, o sube `TIME_WINDOW` |
| `usuario bloqueado N s …` | 5 fallos seguidos | Espera, o desbloquéalo (sección 10) |
| `error de integridad en la cuenta` | La fila del usuario en la BD se ha tocado, o `servidor.key` ha cambiado | Revisa el log; si fue por la clave, borra `secbank.db` y `servidor.key` |
| `sesión no válida o caducada` | Hiciste logout, pasaron 30 min o **se reinició el servidor** (las sesiones están en memoria) | Vuelve a iniciar sesión |
| `replay.py`: `No hay tramas capturadas` | No usaste el proxy en modo `--pasivo` antes | Sigue la demo 7.2 desde el principio |
| `python` abre la Microsoft Store | Alias de Windows | Usa `py`, o desactiva el alias en *Configuración → Aplicaciones → Alias de ejecución* |
| Caracteres raros (`Ã³`) en la consola de Windows | Consola antigua | Usa *Windows Terminal*, o ejecuta `chcp 65001` antes |

---

## 13. Decisiones de seguridad y limitaciones conocidas

Conviene conocerlas para **defenderlas en la corrección** y comentarlas en la memoria.

### Decisiones

- **PBKDF2 en vez de Argon2id.** Está en la librería estándar (`hashlib`) y el enunciado lo acepta expresamente. Con 600 000 iteraciones sigue la recomendación actual de OWASP.
- **Reto-respuesta en el login.** La contraseña no viaja nunca por la red después del registro, y la clave de sesión tampoco: cada lado la calcula por su cuenta. Un espía que lo capture todo no puede firmar mensajes.
- **Nonce + timestamp a la vez.** El nonce solo haría falta recordarlo para siempre. El timestamp solo dejaría un hueco de 2 minutos. Juntos, basta con recordar los nonces de los últimos 4 minutos.
- **El MAC se comprueba antes que el nonce.** Así un atacante no puede llenar ni "gastar" la tabla de nonces.
- **Tiempo constante en todas las comparaciones de secretos.** Firmas de mensajes, prueba de login y firmas de filas usan `hmac.compare_digest`.
- **Firma de filas en la BD.** Cubre la parte de la política sobre la integridad de "usuarios registrados" y "órdenes procesadas" también en el almacenamiento, no solo en la red.
- **Sesiones en memoria.** Nunca tocan el disco, así que no se pueden manipular editando ficheros. Cubre la integridad de las "sesiones activas".
- **Usuario inexistente indistinguible.** Tiene un salt falso pero estable y el mismo mensaje de error.

### Limitaciones, y lo que haría falta para quitarlas

| Limitación | Por qué | Cómo se arreglaría |
|---|---|---|
| El **registro** manda la contraseña en claro | Sin TLS no hay canal seguro para el primer contacto | Alta presencial o por otro canal; o un intercambio Diffie-Hellman autenticado |
| Si roban `secbank.db`, pueden hacerse pasar por los usuarios | `K` es lo que se guarda y basta para hacer login. Es equivalente a la contraseña | Un protocolo PAKE (SRP, OPAQUE), fuera del alcance de la práctica |
| Los **errores** no van firmados | Muchos ocurren antes de tener clave | El cliente ya solo confía en un `OK` firmado; un error falso solo causa denegación de servicio |
| No se comprueba que la cuenta de **origen** sea del usuario | El enunciado no define cuentas | Una tabla `accounts(iban, username)` y una comprobación en `transferir` |
| Las sesiones se pierden al **reiniciar** el servidor | Viven en memoria | Aceptable: basta con volver a iniciar sesión |
| Un único candado para toda la BD | Sencillez | Con mucha carga, un pool de conexiones o un motor como PostgreSQL |
| Sin cifrado del contenido | No lo pide la práctica: se evalúa **integridad**, no confidencialidad | AES-GCM en la capa de aplicación |

---

## 14. Glosario

| Término | En cristiano |
|---|---|
| **Hash (SHA-256)** | "Huella" de un dato: 32 bytes que cambian por completo si cambia un solo bit del original, y a partir de los cuales no se puede recuperar el dato |
| **HMAC** | Hash que además usa una clave secreta. Solo quien tiene la clave puede calcularlo, por eso sirve como **firma** |
| **Salt** | Bytes aleatorios que se mezclan con la contraseña antes de hacer el hash, para que dos contraseñas iguales den resultados distintos y no sirvan las tablas precalculadas (*rainbow tables*) |
| **PBKDF2** | Aplicar HMAC cientos de miles de veces seguidas para que probar contraseñas por fuerza bruta sea muy lento |
| **Nonce** | *Number used once*: un valor aleatorio que se usa una sola vez |
| **Timestamp** | Hora de creación del mensaje, en segundos desde 1970 (hora Unix) |
| **MitM** | *Man-in-the-Middle*: alguien que se pone entre cliente y servidor y puede leer y cambiar el tráfico |
| **Replay** | Reenviar un mensaje legítimo capturado antes, para que se ejecute otra vez |
| **Timing attack** | Deducir un secreto midiendo cuánto tarda el sistema en responder |
| **Tiempo constante** | Una operación que tarda lo mismo sea cual sea el resultado, así que no filtra información |
| **Reto-respuesta** | El servidor manda un valor nuevo (el reto) y el cliente responde con algo que solo puede calcular si conoce el secreto, sin revelarlo |
| **CSPRNG** | Generador de números aleatorios apto para criptografía. En Python es el módulo `secrets` (el módulo `random` **no** sirve) |
| **Forma canónica** | Una forma única y fija de escribir un dato, para que dos partes que firman lo "mismo" firmen exactamente los mismos bytes |
| **.pcap** | Fichero con paquetes de red capturados. Se abre con Wireshark |
