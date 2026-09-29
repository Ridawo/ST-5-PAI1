# Lector de buffer del servidor: lee hasta "\n", parsea el JSON y descarta tramas mal formadas.
import logging
import socketserver

from comun.protocolo import recv_frame, send_frame, sign
from servidor.negocio import atender
from servidor.validacion import Rechazado

log = logging.getLogger("secbank")


class Manejador(socketserver.StreamRequestHandler):
    """Un hilo por cliente conectado. Lee trama a trama hasta que el cliente cierra."""

    def handle(self):
        quien = "%s:%s" % self.client_address
        estado = {}
        log.info("conexión de %s", quien)
        try:
            while True:
                clave = None
                try:
                    msg = recv_frame(self.rfile)
                    if msg is None:
                        break
                    respuesta, clave = atender(msg, estado)
                except Rechazado as e:
                    log.warning("%s RECHAZADO: %s", quien, e)
                    respuesta = {"status": "ERROR", "reason": str(e)}
                except (ValueError, KeyError, TypeError, AttributeError) as e:
                    # JSON roto, faltan campos o tipos raros: se responde error y se sigue, no se cae
                    log.warning("%s trama mal formada: %r", quien, e)
                    respuesta = {"status": "ERROR", "reason": "trama mal formada"}
                send_frame(self.request, sign(respuesta, clave) if clave else respuesta)
        except ConnectionError:
            pass
        log.info("desconexión de %s", quien)
