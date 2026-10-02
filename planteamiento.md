# Planteamiento PAI-1 IntegriDos (Python)

## 1. Qué comunicación usar: sockets TCP (opción A)

De las tres opciones que da el enunciado, se recomienda **sockets TCP**, mandando mensajes JSON separados por `\n`:
- **Todo sale de la librería estándar de Python.** No hace falta instalar nada, y el enunciado prohíbe TLS, así que no hay riesgo de que una librería lo active sola.
- **En Wireshark los mensajes se leen tal cual**, lo que facilita los `.pcap` que hay que entregar.
- **Las demos de ataque son muy fáciles.** Un proxy MitM de unas 30 líneas se pone en medio y cambia el `amount`. Para el replay basta con reenviar una línea que ya se ha capturado.

La rúbrica evalúa igual las tres opciones, así que FastAPI o gRPC solo añadirían trabajo sin dar más nota.

## 2. Tecnologías

| Necesidad | Qué usar | Requisito |
|---|---|---|
| Transporte | `socket` + `socketserver.ThreadingTCPServer` | Opción A |
| Guardar contraseñas | `hashlib.pbkdf2_hmac('sha256', pw, salt, 600_000)`, con un salt de 16 bytes generado con `secrets.token_bytes` | RS1a |
| Firma de mensajes | `hmac.new(key, msg, 'sha256')` | RS2a |
| Claves y nonces | `secrets.token_bytes(32)` (256 bits) | RS2b |
| Comparar firmas | `hmac.compare_digest` (nunca `==`) | RS4 |
| Base de datos | `sqlite3` | Persistencia |
| Tests | `unittest` o `pytest` | Tests y logs |
| Evidencias | `tcpdump -i lo port 5000 -w x.pcap` + Wireshark | Objetivo 4 |

Argon2id también vale, pero requiere instalar `argon2-cffi`. PBKDF2 está en la librería estándar y el enunciado lo acepta expresamente.

## 3. El punto clave: de dónde sale la clave del HMAC sin TLS

Si la contraseña o la clave de sesión viajan en claro, un MitM las ve y puede firmar lo que quiera. Por eso se propone un **reto-respuesta**, en el que la contraseña nunca viaja después del registro:

```
Cliente                                   Servidor
  | LOGIN_INIT {user}                  →   |
  |   ← {salt, server_nonce}               |  el salt se guardó al registrar
  | K = PBKDF2(pw, salt)                   |  K es lo que tiene guardado en la BD
  | LOGIN {user, client_nonce,             |
  |   proof=HMAC(K, server_nonce‖client_nonce)} →  compare_digest(proof)
  |   ← {session_id, firmado}              |  session_key = HMAC(K, "sess"‖nonces)
  | TRANSFER {payload, nonce, ts,          |
  |   session_id, hmac}                →   |  1. la sesión existe y no ha caducado
  |                                        |  2. |now - ts| ≤ 120 s
  |                                        |  3. el nonce no está en la tabla
  |                                        |  4. compare_digest(hmac)
  |                                        |  5. guardar el nonce y la transacción
  |   ← {OK/ERROR, firmado}                |
  | LOGOUT (firmado)                   →   |  borrar la sesión
```

- **Registro:** es el único momento en que la contraseña viaja en claro. No se puede evitar si no hay TLS; hay que decirlo en la memoria como riesgo asumido.
- **Limitación de este diseño:** si alguien roba la BD, puede hacerse pasar por los usuarios, porque lo que se guarda (`K`) equivale a la contraseña. Conviene nombrarlo en la memoria; queda como buena reflexión.
- **Firma canónica:** el HMAC se calcula sobre `json.dumps({action, payload, nonce, timestamp, session_id}, sort_keys=True, separators=(',',':'))`. Así el cliente y el servidor firman exactamente los mismos bytes.
- **Respuestas del servidor:** también van firmadas, así el cliente detecta si alguien las altera.
- **Integridad de lo guardado:** la política exige proteger también usuarios, sesiones y órdenes. Cada fila de transacción puede llevar una columna `row_mac = HMAC(clave_servidor, fila)`, con la clave del servidor en una variable de entorno o un fichero fuera de la BD.

## 4. Base de datos (SQLite)

```
users(username PK, salt, key, failed_attempts, locked_until)   -- RS1b: bloqueo tras 5 fallos, 5 min
sessions(session_id PK, username FK, session_key, expires_at)
nonces(nonce PK, seen_at)                                      -- se borran los que tienen más de 2x la ventana
transactions(tx_id PK, origin, dest, amount, currency, ts, username, row_mac)
```

La `PK` de `username` impide los registros duplicados (RF1c) directamente en la BD. Los usuarios de prueba (RF1b) se crean al arrancar si la BD está vacía.

## 5. Estructura de ficheros (arquitectura de la Figura 2 del enunciado)

```
pai1-st5/
├── comun/protocolo.py      # trama JSON + "\n", firma canónica HMAC, nonce, timestamp
├── cliente/
│   ├── interfaz.py         # módulo de interfaz de usuario (UI)
│   ├── generador.py        # generador de mensajes asegurado
│   └── conexion.py         # interfaz de conexión (socket TCP)
├── servidor/
│   ├── main.py             # arranque del servidor TCP
│   ├── conexion.py         # lector de buffer (hasta "\n")
│   ├── validacion.py       # capa de validación de seguridad (HMAC, no-replay)
│   ├── negocio.py          # capa de lógica de negocio (credenciales, sesiones, transacciones)
│   └── datos.py            # BD de credenciales, nonces y transacciones (SQLite)
├── ataques/                # mitm_proxy.py, replay.py, timing.py
├── tests/                  # test_protocolo.py, test_seguridad.py
├── evidencias/             # pcap/ y logs/
├── docs/                   # memoria
└── README.md               # manual de despliegue
```

## 6. Qué pide la rúbrica y cómo cubrirlo

- **Código (6 puntos):** los fallos que más penalizan son usar `==` para comparar firmas, no tener ventana de tiempo, no borrar los nonces antiguos y que el programa falle con un JSON mal formado. Los cuatro los cubre el diseño de arriba, y cada uno necesita su test.
- **Memoria (3 puntos, 10 páginas como máximo):**
  - diagrama de secuencia (el de arriba),
  - una captura `.pcap` de cada ataque, con análisis y no solo la imagen,
  - explicación del tiempo constante,
  - matriz de trazabilidad (qué fichero y línea implementa cada requisito),
  - apartado sobre el uso de IA.
- **Seguimiento (1 punto):** usar git desde el principio.

La entrega es el **5 de octubre a las 23:59**.
