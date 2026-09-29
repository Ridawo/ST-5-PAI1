# Generador de mensajes asegurado: construye el JSON y le añade HMAC-SHA256, nonce y timestamp.
import secrets
import uuid

from comun.protocolo import derive_key, mac, sign


def registro(usuario, password):
    # Único mensaje con la contraseña en claro: sin TLS no hay forma de evitarlo (riesgo asumido)
    return {"action": "REGISTER", "username": usuario, "password": password}


def login_init(usuario):
    return {"action": "LOGIN_INIT", "username": usuario}


def login(usuario, password, salt_hex, server_nonce_hex):
    """Reto-respuesta: se demuestra que se conoce la contraseña sin mandarla.
    Devuelve (mensaje, clave_sesion). La clave de sesión nunca viaja por la red."""
    clave = derive_key(password, bytes.fromhex(salt_hex))  # la misma K que guarda el servidor
    server_nonce, client_nonce = bytes.fromhex(server_nonce_hex), secrets.token_bytes(16)
    msg = {"action": "LOGIN", "username": usuario, "client_nonce": client_nonce.hex(),
           "proof": mac(clave, server_nonce + client_nonce).hex()}
    return msg, mac(clave, b"session" + server_nonce + client_nonce)


def transferencia(session_id, clave_sesion, origen, destino, importe):
    payload = {"tx_id": str(uuid.uuid4()), "origin_account": origen,
               "destination_account": destino, "amount": importe, "currency": "EUR"}
    return sign({"action": "TRANSFER", "session_id": session_id, "payload": payload}, clave_sesion)


def logout(session_id, clave_sesion):
    return sign({"action": "LOGOUT", "session_id": session_id}, clave_sesion)
