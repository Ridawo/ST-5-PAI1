# Interfaz de conexión del cliente: socket TCP crudo, envía y recibe tramas terminadas en "\n".
import socket

from comun.protocolo import recv_frame, send_frame


class Conexion:
    def __init__(self, host, puerto):
        self.sock = socket.create_connection((host, puerto), timeout=10)
        self.rfile = self.sock.makefile("rb")

    def pedir(self, msg: dict) -> dict:
        """Envía un mensaje y espera la respuesta del servidor."""
        send_frame(self.sock, msg)
        respuesta = recv_frame(self.rfile)
        if respuesta is None:
            raise ConnectionError("el servidor ha cerrado la conexión")
        return respuesta

    def cerrar(self):
        self.sock.close()
