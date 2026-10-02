# Persistencia SQLite: BD de credenciales, sesiones, nonces y transacciones (con MAC por fila).
"""
Todo lo que guarda el servidor:
- users, transactions y nonces van en SQLite (un único fichero secbank.db).
- Las sesiones activas van en memoria: nunca tocan el disco, así que nadie puede editarlas.

Cada fila de users y de transactions lleva un row_mac = HMAC(clave del servidor, fila).
En users el MAC incluye también failed y locked_until, para que no se pueda desbloquear
una cuenta editando la BD.
La clave del servidor está en un fichero aparte (servidor.key), nunca dentro de la BD.
"""
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time

from comun.protocolo import TIME_WINDOW, mac

SESSION_TTL = 1800  # una sesión caduca a los 30 min

ESQUEMA = """
CREATE TABLE IF NOT EXISTS users(
    username     TEXT PRIMARY KEY,           -- la PK impide usuarios duplicados
    salt         BLOB NOT NULL,
    key          BLOB NOT NULL,              -- PBKDF2-HMAC-SHA256(password, salt)
    row_mac      TEXT NOT NULL,
    failed       INTEGER NOT NULL DEFAULT 0,
    locked_until REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS fallos_inexistentes(  -- bloqueo de nombres que no existen: igual que el de users
    username     TEXT PRIMARY KEY,
    failed       INTEGER NOT NULL,
    locked_until REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS nonces(
    nonce   TEXT PRIMARY KEY,                -- la PK hace que un nonce repetido falle al insertar
    seen_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS transactions(
    tx_id    TEXT PRIMARY KEY,
    origin   TEXT NOT NULL,
    dest     TEXT NOT NULL,
    amount   REAL NOT NULL,
    currency TEXT NOT NULL,
    ts       INTEGER NOT NULL,
    username TEXT NOT NULL REFERENCES users,
    row_mac  TEXT NOT NULL
);
"""

_db = None
_lock = threading.Lock()  # un solo lock para toda la BD; con muchos clientes a la vez haría falta un pool
_sesiones = {}            # session_id -> (usuario, clave_sesion, caduca_en)
clave_servidor = b""


def init(ruta_db, ruta_clave):
    """Abre (o crea) la BD y carga la clave del servidor. La primera vez genera una de 256 bits."""
    global _db, clave_servidor
    if not os.path.exists(ruta_clave):
        with open(ruta_clave, "wb") as f:
            f.write(secrets.token_bytes(32))
        os.chmod(ruta_clave, 0o600)  # solo el dueño puede leerla (en Windows no hace nada, no pasa nada)
    with open(ruta_clave, "rb") as f:
        clave_servidor = f.read()
    _db = sqlite3.connect(ruta_db, check_same_thread=False)
    _db.executescript(ESQUEMA)


def _uno(sql, *args):
    with _lock, _db:  # "with _db" hace commit al salir (o rollback si algo falla)
        return _db.execute(sql, args).fetchone()


def _todos(sql, *args):
    with _lock:
        return _db.execute(sql, args).fetchall()


def firma_fila(*campos) -> str:
    campos = [c.hex() if isinstance(c, bytes) else c for c in campos]
    return mac(clave_servidor, json.dumps(campos).encode()).hex()


def fila_integra(row_mac, *campos) -> bool:
    return hmac.compare_digest(str(row_mac).encode(), firma_fila(*campos).encode())


# ---------- credenciales ----------

def crear_usuario(usuario, salt, clave) -> bool:
    """False si el usuario ya existe."""
    with _lock, _db:
        try:
            _db.execute("INSERT INTO users(username, salt, key, row_mac) VALUES (?,?,?,?)",
                        (usuario, salt, clave, ""))
        except sqlite3.IntegrityError:
            return False
        _resellar_usuario(usuario)  # firma la fila recién creada (failed=0, locked_until=0)
        return True


def _resellar_usuario(usuario) -> None:
    """Vuelve a calcular el row_mac del usuario con lo que hay en la fila.
    Hay que llamarla con el lock cogido y dentro de la transacción."""
    salt, clave, failed, locked = _db.execute(
        "SELECT salt, key, failed, locked_until FROM users WHERE username=?", (usuario,)).fetchone()
    _db.execute("UPDATE users SET row_mac=? WHERE username=?",
                (firma_fila(usuario, salt, clave, failed, locked), usuario))


def leer_usuario(usuario):
    """Devuelve (salt, clave, bloqueado_hasta, fila_integra) o None si no existe."""
    fila = _uno("SELECT salt, key, row_mac, failed, locked_until FROM users WHERE username=?", usuario)
    if fila is None:
        return None
    salt, clave, row_mac, failed, bloqueado_hasta = fila
    return salt, clave, bloqueado_hasta, fila_integra(row_mac, usuario, salt, clave, failed, bloqueado_hasta)


def tras_fallo(failed, locked_until, max_fallos, bloqueo_seg):
    """Regla del bloqueo: un fallo más; al llegar al tope se reinicia el contador y se bloquea."""
    failed += 1
    if failed >= max_fallos:
        return 0, time.time() + bloqueo_seg
    return failed, locked_until


def apuntar_fallo(usuario, max_fallos, bloqueo_seg) -> None:
    """Suma un intento fallido. Al llegar a max_fallos, bloquea la cuenta bloqueo_seg segundos.
    Recalcula el row_mac para que el contador y el bloqueo queden protegidos por integridad."""
    with _lock, _db:
        fila = _db.execute("SELECT failed, locked_until FROM users WHERE username=?", (usuario,)).fetchone()
        if fila is None:
            return
        failed, locked_until = tras_fallo(*fila, max_fallos, bloqueo_seg)
        _db.execute("UPDATE users SET failed=?, locked_until=? WHERE username=?", (failed, locked_until, usuario))
        _resellar_usuario(usuario)


def bloqueo_inexistente(usuario) -> float:
    """Hasta cuándo está 'bloqueado' un nombre que no existe (0 si no lo está)."""
    fila = _uno("SELECT locked_until FROM fallos_inexistentes WHERE username=?", usuario)
    return fila[0] if fila else 0.0


def apuntar_fallo_inexistente(usuario, max_fallos, bloqueo_seg) -> None:
    """apuntar_fallo para un nombre que no existe, con la misma regla y también en disco:
    así ni el mensaje de bloqueo ni un reinicio del servidor delatan qué usuarios existen."""
    with _lock, _db:
        fila = _db.execute("SELECT failed, locked_until FROM fallos_inexistentes WHERE username=?",
                           (usuario,)).fetchone() or (0, 0.0)
        _db.execute("INSERT OR REPLACE INTO fallos_inexistentes VALUES (?,?,?)",
                    (usuario, *tras_fallo(*fila, max_fallos, bloqueo_seg)))


def limpiar_fallos(usuario) -> None:
    with _lock, _db:
        _db.execute("UPDATE users SET failed = 0 WHERE username=?", (usuario,))
        _resellar_usuario(usuario)


# ---------- nonces (anti-replay) ----------

def registrar_nonce(nonce) -> bool:
    """Guarda el nonce. False si ya estaba (replay)."""
    ahora = time.time()
    with _lock, _db:
        # Se borran los de hace más de 2 ventanas: un mensaje con ese nonce fallaría
        # igualmente por timestamp, así que ya no hace falta recordarlos.
        _db.execute("DELETE FROM nonces WHERE seen_at < ?", (ahora - 2 * TIME_WINDOW,))
        try:
            _db.execute("INSERT INTO nonces VALUES (?,?)", (nonce, ahora))
            return True
        except sqlite3.IntegrityError:
            return False


# ---------- transacciones ----------

def guardar_transaccion(tx_id, origen, destino, importe, moneda, ts, usuario) -> bool:
    """False si el tx_id ya existía."""
    fila = (tx_id, origen, destino, float(importe), moneda, ts, usuario)  # float(): 100 y 100.0 deben firmar igual
    try:
        _uno("INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?)", *fila, firma_fila(*fila))
        return True
    except sqlite3.IntegrityError:
        return False


def filas_corruptas() -> list[str]:
    """Revisa toda la BD y devuelve las filas cuyo row_mac no cuadra (alguien las ha tocado)."""
    malas = [f"users/{u}" for u, s, k, fa, lu, m in
             _todos("SELECT username, salt, key, failed, locked_until, row_mac FROM users")
             if not fila_integra(m, u, s, k, fa, lu)]
    malas += [f"transactions/{f[0]}" for f in _todos("SELECT * FROM transactions")
              if not fila_integra(f[7], *f[:7])]
    return malas


# ---------- sesiones (en memoria) ----------

def crear_sesion(usuario, clave_sesion) -> str:
    sid = secrets.token_hex(32)
    _sesiones[sid] = (usuario, clave_sesion, time.time() + SESSION_TTL)
    return sid


def leer_sesion(sid):
    """Devuelve (usuario, clave_sesion) o None si no existe o ha caducado."""
    s = _sesiones.get(sid)
    if s is None or s[2] < time.time():
        _sesiones.pop(sid, None)
        return None
    return s[0], s[1]


def borrar_sesion(sid) -> None:
    _sesiones.pop(sid, None)
