# Capa de validación de seguridad: verificación de integridad/autenticidad (HMAC) y de no-replay (nonce + timestamp).
import hmac
import time

from comun.protocolo import TIME_WINDOW, mac, verify_mac
from servidor import datos


class Rechazado(Exception):
    """Mensaje rechazado. El texto se devuelve al cliente y se apunta en el log."""


def comprobar_prueba_login(clave, server_nonce, client_nonce, prueba) -> bool:
    """El cliente demuestra que conoce la contraseña sin enviarla: manda HMAC(K, sn‖cn)."""
    esperado = mac(clave, server_nonce + client_nonce).hex().encode()
    return hmac.compare_digest(esperado, str(prueba).encode())  # tiempo constante (RS4)


def verificar_mensaje(msg):
    """Todas las comprobaciones de un mensaje dentro de una sesión.
    Devuelve (usuario, clave_sesion) o lanza Rechazado."""
    sesion = datos.leer_sesion(msg["session_id"])
    if sesion is None:
        raise Rechazado("sesión no válida o caducada")
    usuario, clave = sesion
    # 1º el MAC: así alguien sin la clave no puede llenar la tabla de nonces con basura
    if not verify_mac(msg, clave):
        raise Rechazado("MAC inválido: el mensaje ha sido alterado")      # MitM (RS2)
    if abs(time.time() - msg["timestamp"]) > TIME_WINDOW:
        raise Rechazado("timestamp fuera de la ventana permitida")        # replay antiguo (RS3)
    if not datos.registrar_nonce(msg["nonce"]):
        raise Rechazado("nonce repetido: posible ataque de replay")       # replay reciente (RS3)
    return usuario, clave
