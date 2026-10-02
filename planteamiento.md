# Planteamiento PAI-1 IntegriDos (Python)

## 1. Qué comunicación usar: sockets TCP (opción A)

De las tres opciones del enunciado elegimos sockets TCP, con mensajes JSON separados por `\n`. Los motivos:
- Todo está en la librería estándar de Python, no hay que instalar nada y no hay riesgo de que una librería active TLS por su cuenta (el enunciado lo prohíbe).
- En Wireshark los mensajes se leen tal cual, y eso facilita los `.pcap`.
- Los ataques son fáciles de montar: el proxy MitM es un script corto que cambia el `amount`, y para el replay basta con reenviar una línea capturada.

FastAPI o gRPC nos habrían obligado a meter dependencias sin ganar nada para lo que se pide.

## 2. Tecnologías

| Necesidad | Qué usar | Requisito |
|---|---|---|
| Transporte | `socket` + `socketserver.ThreadingTCPServer` | Opción A |
| Guardar contraseñas | `hashlib.pbkdf2_hmac('sha256', pw, salt, 600_000)`, con un salt de 16 bytes generado con `secrets.token_bytes` | RS1a |
| Firma de mensajes | `hmac.new(key, msg, 'sha256')` | RS2a |
| Claves y nonces | `secrets.token_bytes(32)` para claves (256 bits), 16 bytes para salt y nonces | RS2b |
| Comparar firmas | `hmac.compare_digest` (nunca `==`) | RS4 |
| Base de datos | `sqlite3` | Persistencia |
| Tests | `unittest` o `pytest` | Tests y logs |
| Evidencias | `tcpdump -i lo port 5000 -w x.pcap` + Wireshark | Objetivo 4 |

Argon2id también valdría, pero hay que instalar `argon2-cffi`. PBKDF2 viene en la librería estándar y el enunciado lo acepta.

## 3. De dónde sale la clave del HMAC sin TLS

Si la contraseña o la clave de sesión viajan en claro, un MitM las ve y puede firmar lo que quiera. Por eso el login es un reto-respuesta y la contraseña no vuelve a viajar después del registro:

```
Cliente                                   Servidor
  | LOGIN_INIT {user}                  →   |
  |   ← {salt, server_nonce}               |  el salt se guardó al registrar
  | K = PBKDF2(pw, salt)                   |  K es lo que tiene guardado en la BD
  | LOGIN {user, client_nonce,             |
  |   proof=HMAC(K, server_nonce‖client_nonce)} →  compare_digest(proof)
  |   ← {session_id, firmado}              |  session_key = HMAC(K, "session"‖nonces)
  | TRANSFER {payload, nonce, ts,          |
  |   session_id, hmac}                →   |  1. la sesión existe y no ha caducado
  |                                        |  2. compare_digest(hmac)
  |                                        |  3. |now - ts| ≤ 120 s
  |                                        |  4. el nonce no está en la tabla
  |                                        |  5. guardar el nonce y la transacción
  |   ← {OK/ERROR, firmado}                |
  | LOGOUT (firmado)                   →   |  borrar la sesión
```

- Registro: es el único momento en que la contraseña viaja en claro. Sin TLS no se puede evitar, así que lo dejamos como riesgo asumido.
- Limitación: si alguien roba la BD puede hacerse pasar por los usuarios, porque lo que se guarda (`K`) equivale a la contraseña. Lo comentamos en la memoria.
- Firma canónica: el HMAC se calcula sobre `json.dumps({action, payload, nonce, timestamp, session_id}, sort_keys=True, separators=(',',':'))`. Así el cliente y el servidor firman exactamente los mismos bytes.
- Respuestas del servidor: también van firmadas, así el cliente detecta si alguien las altera.
- Integridad de lo guardado: la política pide proteger también usuarios, sesiones y órdenes. Cada fila de `users` y de `transactions` lleva una columna `row_mac = HMAC(clave_servidor, fila)`, con la clave del servidor en un fichero fuera de la BD.

## 4. Base de datos (SQLite)

```
users(username PK, salt, key, row_mac, failed, locked_until)   -- RS1b: bloqueo tras 5 fallos, 5 min
fallos_inexistentes(username PK, failed, locked_until)         -- mismo bloqueo para nombres que no existen
nonces(nonce PK, seen_at)                                      -- se borran los que tienen más de 2x la ventana
transactions(tx_id PK, origin, dest, amount, currency, ts, username, row_mac)
```

Las sesiones no van en la BD: se guardan en memoria en el servidor. La `PK` de `username` impide los registros duplicados (RF1c) directamente en la BD. Los usuarios de prueba (RF1b) se crean al arrancar si la BD está vacía.

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

## 6. Entrega

- Código: comparar firmas con `compare_digest` y nunca con `==`, ventana de tiempo, borrado de nonces antiguos y que un JSON mal formado no tumbe el servidor. Cada punto con su test.
- Memoria (10 páginas como máximo): diagrama de secuencia, una captura `.pcap` de cada ataque con su análisis, explicación del tiempo constante, matriz de trazabilidad y el apartado sobre el uso de IA.
- Git desde el principio.

Fecha de entrega: 5 de octubre a las 23:59.
