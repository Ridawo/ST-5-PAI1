# PAI1-ST5 · IntegriDos

Cliente-servidor de transferencias bancarias sobre **TCP crudo sin TLS**. La integridad y la autenticidad se garantizan en la capa de aplicación con HMAC-SHA256, nonces, timestamps y comparación en tiempo constante.

Solo usa la librería estándar de Python (`socket`, `hashlib`, `hmac`, `secrets`, `sqlite3`), así que **no hay que instalar nada**.

> Documento extenso con demos paso a paso y capturas: [`guia.md`](guia.md).

## Requisitos

- Python **3.10 o superior** (Linux, macOS o Windows).
- Todos los comandos se lanzan **desde la raíz del repo**. En Windows, si `python` no funciona, usa `py`.

## Estructura del repositorio

```
PAI1-ST5/
├── comun/
│   └── protocolo.py       Núcleo criptográfico compartido por cliente y servidor:
│                          firma canónica, HMAC-SHA256, nonce+timestamp, PBKDF2,
│                          compare_digest (tiempo constante) y lectura de tramas JSON.
│
├── servidor/
│   ├── main.py            Punto de entrada del servidor. Arranca el TCP en 5000, crea
│   │                      la BD y la clave si no existen y avisa de filas manipuladas.
│   ├── conexion.py        Manejador TCP: una hebra por cliente, lee tramas y las reparte.
│   ├── negocio.py         Lógica bancaria: registro, login (reto-respuesta), bloqueo por
│   │                      fallos, transferencia y logout. Aquí se aplican los requisitos.
│   ├── validacion.py      Comprobaciones de cada mensaje: MAC, nonce, timestamp, formato.
│   └── datos.py           Capa SQLite: usuarios, sesiones, transacciones y nonces vistos.
│                          Firma cada fila con la clave del servidor para detectar cambios.
│
├── cliente/
│   ├── interfaz.py        Menú en consola (registro, login, transferencia, logout).
│   ├── generador.py       Construye y firma los mensajes que se envían al servidor.
│   └── conexion.py        Envoltorio del socket: manda una trama y espera la respuesta.
│
├── ataques/               Demostraciones de que las defensas funcionan (todas fallan):
│   ├── mitm_proxy.py      Man-in-the-Middle: proxy que altera el importe -> "MAC inválido".
│   ├── replay.py          Reenvía una trama capturada -> "nonce repetido" / timestamp viejo.
│   └── timing.py          Compara `==` vs `compare_digest` para enseñar la fuga de tiempo.
│
├── tests/
│   ├── test_protocolo.py  Tests unitarios de la criptografía (firma, MAC, tramas raras).
│   └── test_seguridad.py  Tests de extremo a extremo: levanta un servidor real y lo ataca.
│
├── evidencias/            Salidas para el entregable (log del servidor y capturas .pcap).
├── guia.md                Guía completa: teoría, demos paso a paso y solución de problemas.
├── planteamiento.md       Decisiones de diseño y reparto de la práctica.
└── README.md              Este fichero.
```

`secbank.db` (la base de datos) y `servidor.key` (la clave con la que el servidor firma
las filas) **no están en el repo**: se generan solos en el primer arranque.

## Guía rápida (para corregir)

**1. Arrancar el servidor** (crea `secbank.db` y `servidor.key` la primera vez):

```bash
python -m servidor.main              # escucha en 127.0.0.1:5000
```

**2. En otra terminal, el cliente:**

```bash
python -m cliente.interfaz           # menú en consola
```

**3. Usuarios de prueba ya sembrados:**

| Usuario | Contraseña |
|---|---|
| alice | alice1234 |
| bob | bob12345 |
| carol | carol1234 |

Las cuentas (IBAN) son `ES` + 22 dígitos, p. ej. `ES1234567890123456789012`.

El log del servidor se escribe a la vez en consola y en `evidencias/logs/servidor.log`.

## Tests

```bash
python -m unittest discover tests -v
```

Los tests de `test_seguridad.py` **levantan un servidor real** en un puerto libre con una
BD temporal y hablan con él por TCP. Con `-v` verás, intercalada con cada test, la
actividad del servidor prefijada con `[srv]`:

```
test_login_correcto_con_respuesta_firmada ...     [srv] INFO    conexión de 127.0.0.1:38762
    [srv] INFO    login OK alice
ok
test_bloqueo_tras_5_fallos ...     [srv] WARNING login FALLIDO eve
    [srv] WARNING 127.0.0.1:38748 RECHAZADO: usuario bloqueado 299 s por demasiados intentos
ok
```

Así se ve qué está pasando por dentro en cada caso (login, bloqueo, MitM, replay,
detección de manipulación de la BD...). Tardan ~1-2 min porque PBKDF2 usa 600.000
iteraciones a propósito.

## Ataques de demostración

Los tres confirman que las defensas hacen su trabajo. (Detalle paso a paso en `guia.md`.)

| Ataque | Cómo | Resultado esperado |
|---|---|---|
| MitM | `python -m ataques.mitm_proxy` y el cliente con `python -m cliente.interfaz 127.0.0.1 5001` | El proxy multiplica el importe por 100 y cambia el destino. El servidor responde `MAC inválido`. |
| Replay | 1. `python -m ataques.mitm_proxy --pasivo`, conectas el cliente al 5001 y haces una transferencia. 2. **Sin cerrar sesión**, lanzas `python -m ataques.replay` | `nonce repetido` si han pasado menos de 120 s; `timestamp fuera de la ventana` si han pasado más. |
| Timing | `python -m ataques.timing` | `==` tarda más cuantos más bytes acierta; `compare_digest` tarda siempre lo mismo. Los datos quedan en `evidencias/timing.csv`. |

> Orden del MitM: **1)** servidor (5000), **2)** proxy (5001→5000), **3)** cliente al **5001**.

## Captura de tráfico (.pcap)

- **Linux:** `sudo tcpdump -i lo -w evidencias/pcap/normal.pcap 'tcp port 5000 or tcp port 5001'`
- **Windows:** abre Wireshark (con Npcap), elige la interfaz *Adapter for loopback traffic capture*, pon el filtro `tcp.port == 5000 || tcp.port == 5001` y usa *Guardar como* en `evidencias/pcap/`.
- **En Wireshark:** clic derecho sobre un paquete → *Seguir → Secuencia TCP* para ver los JSON en claro con su `hmac`, `nonce` y `timestamp`.

Se graba una captura por escenario: `normal.pcap`, `mitm.pcap` y `replay.pcap`.

## Protocolo

| Acción | Envía el cliente | Responde el servidor |
|---|---|---|
| `REGISTER` | `username`, `password` (en claro, riesgo asumido) | `OK` / `ERROR` |
| `LOGIN_INIT` | `username` | `salt`, `server_nonce` |
| `LOGIN` | `client_nonce`, `proof = HMAC(K, sn‖cn)` con `K = PBKDF2(password, salt)` | `session_id`, firmado con la clave de sesión |
| `TRANSFER` | `session_id`, `payload` + `nonce`, `timestamp`, `hmac` | `tx_id`, firmado |
| `LOGOUT` | `session_id` + `nonce`, `timestamp`, `hmac` | `OK`, firmado |

- **La contraseña no viaja nunca después del registro.**
- **La clave de sesión tampoco viaja:** es `HMAC(K, "session"‖sn‖cn)` y la calculan cliente y servidor cada uno por su lado.
- **Errores:** van sin firmar. El cliente solo se fía de un `OK` que llegue con firma válida.

## Dónde se implementa cada requisito

| Requisito | Fichero y función |
|---|---|
| RF1a Registro | `servidor/negocio.py` → `registrar` |
| RF1b Usuarios de prueba | `servidor/negocio.py` → `USUARIOS_PRUEBA`, `sembrar` |
| RF1c Sin duplicados | `servidor/datos.py` → `PRIMARY KEY` de `users`, `crear_usuario` |
| RF1d Sesiones y logout | `servidor/datos.py` → `crear_sesion`, `leer_sesion`, `borrar_sesion`; `negocio.py` → `LOGOUT` |
| RF2 Transacciones | `cliente/generador.py` → `transferencia`; `servidor/negocio.py` → `validar_transaccion`, `transferir` |
| RS1a PBKDF2 + salt | `comun/protocolo.py` → `derive_key`; `servidor/negocio.py` → `registrar` |
| RS1b Bloqueo por fallos | `servidor/datos.py` → `apuntar_fallo`; `servidor/negocio.py` → `login` |
| RS2a HMAC-SHA256 | `comun/protocolo.py` → `mac`, `canonical`, `sign`, `verify_mac` |
| RS2b Claves de 256 bits con CSPRNG | `secrets.token_bytes` en `protocolo.py`, `datos.py` y `generador.py` |
| RS3 Nonce + timestamp | `servidor/validacion.py` → `verificar_mensaje`; `servidor/datos.py` → `registrar_nonce` |
| RS4 Tiempo constante | `hmac.compare_digest` en `protocolo.py` → `verify_mac`, `validacion.py` → `comprobar_prueba_login` y `datos.py` → `fila_integra` |
| Integridad de lo almacenado | `servidor/datos.py` → `firma_fila`, `filas_corruptas` (se revisa al arrancar) |
