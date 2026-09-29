# Protocolo común cliente/servidor: formato de trama JSON + "\n", firma canónica HMAC-SHA256, nonce y timestamp.
"""
Cada mensaje viaja como un JSON en una sola línea terminada en "\n" por un socket TCP
sin cifrar (el enunciado prohíbe TLS). La seguridad la pone el HMAC-SHA256 que va dentro
de cada mensaje, calculado con una clave que solo conocen el cliente y el servidor.

Todo sale de la librería estándar de Python: hashlib, hmac, secrets y json.
"""
import hashlib
import hmac
import json
import secrets
import time

PBKDF2_ITERS = 600_000   # recomendación OWASP para PBKDF2-HMAC-SHA256
TIME_WINDOW = 120        # segundos de margen entre el reloj del cliente y el del servidor
MAX_FRAME = 64 * 1024    # una línea más larga se descarta (evita que nos agoten la memoria)


def derive_key(password: str, salt: bytes) -> bytes:
    """Convierte la contraseña en una clave de 256 bits. Es lenta a propósito (fuerza bruta cara)."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERS)


def mac(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256: 32 bytes que solo puede calcular quien tenga la clave."""
    return hmac.new(key, data, hashlib.sha256).digest()


def canonical(msg: dict) -> bytes:
    """Bytes exactos que se firman: todo el mensaje menos el campo hmac, con las claves
    ordenadas y sin espacios. Así cliente y servidor firman lo mismo aunque el JSON
    llegue con los campos en otro orden."""
    cuerpo = {k: v for k, v in msg.items() if k != "hmac"}
    return json.dumps(cuerpo, sort_keys=True, separators=(",", ":")).encode()


def sign(msg: dict, key: bytes) -> dict:
    """Añade nonce, timestamp y HMAC. El nonce y el timestamp entran dentro de la firma
    (principio de Horton): si alguien los cambia para colar un replay, el MAC deja de cuadrar."""
    msg = dict(msg, nonce=secrets.token_hex(16), timestamp=int(time.time()))
    msg["hmac"] = mac(key, canonical(msg)).hex()
    return msg


def verify_mac(msg: dict, key: bytes) -> bool:
    """RS4: hmac.compare_digest tarda lo mismo acierte o falle, así un atacante no puede ir
    adivinando la firma byte a byte midiendo microsegundos (un == normal para en el primer fallo)."""
    esperado = mac(key, canonical(msg)).hex().encode()
    return hmac.compare_digest(esperado, str(msg.get("hmac", "")).encode())


def send_frame(sock, msg: dict) -> None:
    sock.sendall(json.dumps(msg).encode() + b"\n")


def recv_frame(rfile) -> dict | None:
    """Lee una línea del socket. Devuelve None si el otro extremo cerró la conexión
    y lanza ValueError si lo que llega no es un objeto JSON válido."""
    linea = rfile.readline(MAX_FRAME + 1)
    if not linea:
        return None
    if len(linea) > MAX_FRAME:
        raise ValueError("trama demasiado grande")
    msg = json.loads(linea)  # si no es JSON lanza JSONDecodeError, que es un ValueError
    if not isinstance(msg, dict):
        raise ValueError("la trama no es un objeto JSON")
    return msg
