# PAI1-ST5 · IntegriDos

Cliente-servidor de transferencias bancarias sobre **TCP crudo sin TLS**. La integridad y la autenticidad se garantizan en la capa de aplicación con HMAC-SHA256, nonces, timestamps y comparación en tiempo constante.

Solo usa la librería estándar de Python (`socket`, `hashlib`, `hmac`, `secrets`, `sqlite3`), así que no hay que instalar nada.

## Requisitos

- Python **3.10 o superior** (Linux, macOS o Windows).
- Todos los comandos se lanzan **desde la raíz del repo**. En Windows, si `python` no funciona, usa `py`.

## Arranque

```bash
python -m servidor.main              # terminal 1: servidor en 127.0.0.1:5000
python -m cliente.interfaz           # terminal 2: cliente (menú en consola)
```

- **Primer arranque:** el servidor crea `secbank.db` (la BD) y `servidor.key` (la clave con la que firma las filas de la BD). Ninguno de los dos se sube al repo.
- **Log:** se escribe en `evidencias/logs/servidor.log`.
- **Usuarios de prueba:**

| Usuario | Contraseña |
|---|---|
| alice | alice1234 |
| bob | bob12345 |
| carol | carol1234 |

- **Cuentas:** los IBAN tienen el formato `ES` + 22 dígitos, por ejemplo `ES1234567890123456789012`.

## Tests

```bash
python -m unittest discover tests -v
```

## Ataques de demostración

| Ataque | Cómo | Resultado esperado |
|---|---|---|
| MitM | `python -m ataques.mitm_proxy` y el cliente con `python -m cliente.interfaz 127.0.0.1 5001` | El proxy multiplica el importe por 100 y cambia el destino. El servidor responde `MAC inválido`. |
| Replay | 1. `python -m ataques.mitm_proxy --pasivo`, conectas el cliente al 5001 y haces una transferencia. 2. **Sin cerrar sesión**, lanzas `python -m ataques.replay` | `nonce repetido` si han pasado menos de 120 s; `timestamp fuera de la ventana` si han pasado más. |
| Timing | `python -m ataques.timing` | `==` tarda más cuantos más bytes acierta; `compare_digest` tarda siempre lo mismo. Los datos quedan en `evidencias/timing.csv`. |

## Captura de tráfico (.pcap)

- **Linux:** `sudo tcpdump -i lo -w evidencias/pcap/normal.pcap 'tcp port 5000 or tcp port 5001'`
- **Windows:** abre Wireshark (con Npcap), elige la interfaz *Adapter for loopback traffic capture*, pon el filtro `tcp.port == 5000 || tcp.port == 5001` y usa *Guardar como* en `evidencias/pcap/`.
- **En Wireshark:** clic derecho sobre un paquete → *Seguir → Secuencia TCP* para ver los JSON en claro con su `hmac`, `nonce` y `timestamp`.

Hay que grabar una captura por escenario: `normal.pcap`, `mitm.pcap` y `replay.pcap`.

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
