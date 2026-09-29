# Capa de lógica de negocio: registro, login (hash + salt), sesiones, bloqueo por intentos y procesado de transacciones.
"""
Acciones que entiende el servidor (campo "action" de cada trama):
    REGISTER    {username, password}                   -> la contraseña va en claro: único momento, riesgo asumido
    LOGIN_INIT  {username}                             -> {salt, server_nonce}
    LOGIN       {username, client_nonce, proof}        -> {session_id}                 (respuesta firmada)
    TRANSFER    {session_id, payload} + nonce/ts/hmac  -> {tx_id}                      (respuesta firmada)
    LOGOUT      {session_id} + nonce/ts/hmac           -> {}                           (respuesta firmada)
Los errores se responden sin firmar: el cliente solo se fía de un OK con firma válida.
"""
import logging
import re
import secrets
import time
import uuid

from comun.protocolo import derive_key, mac
from servidor import datos
from servidor.validacion import Rechazado, comprobar_prueba_login, verificar_mensaje

MAX_FALLOS, BLOQUEO_SEG = 5, 300  # RS1b: 5 fallos seguidos -> 5 minutos bloqueado
USUARIOS_PRUEBA = [("alice", "alice1234"), ("bob", "bob12345"), ("carol", "carol1234")]
IBAN = re.compile(r"[A-Z]{2}\d{22}")

log = logging.getLogger("secbank")


def atender(msg, estado):
    """Procesa una trama ya parseada. Devuelve (respuesta, clave con la que firmarla o None).
    'estado' es propio de cada conexión y guarda el reto de login pendiente."""
    accion = msg["action"]
    if accion == "REGISTER":
        registrar(msg["username"], msg["password"])
        return {"status": "OK"}, None
    if accion == "LOGIN_INIT":
        return login_init(str(msg["username"]), estado), None
    if accion == "LOGIN":
        return login(msg, estado)
    if accion == "TRANSFER":
        return transferir(msg)
    if accion == "LOGOUT":
        usuario, clave = verificar_mensaje(msg)
        datos.borrar_sesion(msg["session_id"])
        log.info("logout %s", usuario)
        return {"status": "OK"}, clave
    raise Rechazado(f"acción desconocida: {accion}")


# ---------- usuarios ----------

def registrar(usuario, password):
    if not (isinstance(usuario, str) and usuario.isalnum() and len(usuario) <= 32):
        raise Rechazado("usuario no válido (solo letras y números, máximo 32)")
    if not (isinstance(password, str) and len(password) >= 8):
        raise Rechazado("la contraseña debe tener al menos 8 caracteres")
    salt = secrets.token_bytes(16)  # RS1a: salt aleatorio y distinto para cada usuario
    if not datos.crear_usuario(usuario, salt, derive_key(password, salt)):
        raise Rechazado("el usuario ya existe")
    log.info("registro OK %s", usuario)


def sembrar():
    """Usuarios de prueba (RF1b). Solo se crean si no existen."""
    for usuario, password in USUARIOS_PRUEBA:
        if datos.leer_usuario(usuario) is None:
            registrar(usuario, password)


def login_init(usuario, estado):
    fila = datos.leer_usuario(usuario)
    # Si el usuario no existe se inventa un salt, siempre el mismo para ese nombre:
    # así desde fuera no se puede saber qué usuarios existen.
    salt = fila[0] if fila else mac(datos.clave_servidor, usuario.encode())[:16]
    estado["reto"] = (usuario, secrets.token_bytes(16))
    return {"status": "OK", "salt": salt.hex(), "server_nonce": estado["reto"][1].hex()}


def login(msg, estado):
    reto = estado.pop("reto", None)  # cada reto sirve para un solo intento
    if reto is None or reto[0] != msg["username"]:
        raise Rechazado("hay que pedir LOGIN_INIT antes de LOGIN")
    usuario, server_nonce = reto
    client_nonce = bytes.fromhex(msg["client_nonce"])
    fila = datos.leer_usuario(usuario)
    if fila is None:
        raise Rechazado("credenciales incorrectas")
    _, clave, bloqueado_hasta, integra = fila
    if not integra:
        log.error("INTEGRIDAD BD: credenciales de %s manipuladas", usuario)
        raise Rechazado("error de integridad en la cuenta, contacta con el banco")
    if bloqueado_hasta > time.time():
        raise Rechazado(f"usuario bloqueado {int(bloqueado_hasta - time.time())} s por demasiados intentos")
    if not comprobar_prueba_login(clave, server_nonce, client_nonce, msg["proof"]):
        datos.apuntar_fallo(usuario, MAX_FALLOS, BLOQUEO_SEG)
        log.warning("login FALLIDO %s", usuario)
        raise Rechazado("credenciales incorrectas")
    datos.limpiar_fallos(usuario)
    # El cliente calcula la misma clave por su lado: la clave de sesión nunca viaja por la red
    clave_sesion = mac(clave, b"session" + server_nonce + client_nonce)
    sid = datos.crear_sesion(usuario, clave_sesion)
    log.info("login OK %s", usuario)
    return {"status": "OK", "session_id": sid}, clave_sesion


# ---------- transacciones ----------

def validar_transaccion(p):
    try:
        if uuid.UUID(str(p["tx_id"])).version != 4:
            raise ValueError
    except ValueError:
        raise Rechazado("tx_id debe ser un UUIDv4")
    for campo in ("origin_account", "destination_account"):
        if not (isinstance(p[campo], str) and IBAN.fullmatch(p[campo])):
            raise Rechazado(f"{campo} no es un IBAN válido (2 letras + 22 dígitos)")
    if p["origin_account"] == p["destination_account"]:
        raise Rechazado("la cuenta de origen y la de destino son la misma")
    importe = p["amount"]
    if isinstance(importe, bool) or not isinstance(importe, (int, float)) \
            or not 0 < importe <= 1_000_000 or round(importe, 2) != importe:
        raise Rechazado("importe no válido (mayor que 0, máximo 1.000.000 y 2 decimales)")
    if p["currency"] != "EUR":
        raise Rechazado("solo se admite EUR")


def transferir(msg):
    usuario, clave = verificar_mensaje(msg)  # sesión, MAC, timestamp y nonce
    p = msg["payload"]
    validar_transaccion(p)
    # ponytail: no se comprueba que origin_account sea del usuario; el enunciado no define cuentas
    if not datos.guardar_transaccion(p["tx_id"], p["origin_account"], p["destination_account"],
                                     p["amount"], p["currency"], msg["timestamp"], usuario):
        raise Rechazado("tx_id repetido")
    log.info("TRANSFER OK %s %s: %s -> %s %.2f EUR", usuario, p["tx_id"],
             p["origin_account"], p["destination_account"], p["amount"])
    return {"status": "OK", "tx_id": p["tx_id"]}, clave
