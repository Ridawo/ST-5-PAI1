# Punto de entrada del servidor: arranca el servidor TCP y reparte cada trama a su capa.
"""
Uso (desde la raíz del repo, igual en Linux y Windows):
    python -m servidor.main [host] [puerto]        por defecto 127.0.0.1 5000
Log en evidencias/logs/servidor.log. La BD (secbank.db) y la clave (servidor.key) se crean solas.
"""
import logging
import os
import socketserver
import sys
from pathlib import Path

from servidor import datos, negocio
from servidor.conexion import Manejador

RAIZ = Path(__file__).resolve().parent.parent
log = logging.getLogger("secbank")


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    puerto = int(sys.argv[2]) if len(sys.argv) > 2 else 5000

    carpeta_logs = RAIZ / "evidencias" / "logs"
    carpeta_logs.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s",
                        handlers=[logging.FileHandler(carpeta_logs / "servidor.log", encoding="utf-8"),
                                  logging.StreamHandler()])

    datos.init(RAIZ / "secbank.db", RAIZ / "servidor.key")
    negocio.sembrar()
    for fila in datos.filas_corruptas():
        log.error("INTEGRIDAD BD: la fila %s ha sido manipulada", fila)

    # En Windows SO_REUSEADDR deja que otro proceso "robe" el puerto, así que solo se activa en Linux
    socketserver.ThreadingTCPServer.allow_reuse_address = os.name != "nt"
    socketserver.ThreadingTCPServer.daemon_threads = True
    with socketserver.ThreadingTCPServer((host, puerto), Manejador) as srv:
        log.info("SecBank escuchando en %s:%d (TCP sin TLS, a propósito)", host, puerto)
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            log.info("servidor parado")


if __name__ == "__main__":
    main()
