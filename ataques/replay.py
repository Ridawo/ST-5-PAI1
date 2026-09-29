# Ataque Replay: reenvía al servidor una trama capturada previamente.
"""
    python -m ataques.replay [fichero] [host] [puerto]
Por defecto reenvía la última línea de evidencias/logs/capturadas.jsonl (la guarda el MitM en
modo --pasivo) a 127.0.0.1:5000. La trama se manda tal cual, byte a byte, con su HMAC original.

Resultado esperado: "nonce repetido" si han pasado menos de 120 s, "timestamp fuera de la
ventana" si han pasado más. Hazlo antes de cerrar la sesión: si no, el motivo será "sesión no válida".
"""
import socket
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent


def main():
    fichero = Path(sys.argv[1]) if len(sys.argv) > 1 else RAIZ / "evidencias" / "logs" / "capturadas.jsonl"
    host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    puerto = int(sys.argv[3]) if len(sys.argv) > 3 else 5000
    lineas = fichero.read_bytes().splitlines() if fichero.exists() else []
    if not lineas:
        sys.exit(f"No hay tramas capturadas en {fichero}. Usa antes: python -m ataques.mitm_proxy --pasivo")

    trama = lineas[-1] + b"\n"
    print(f"[Replay] reenviando {len(trama)} bytes capturados a {host}:{puerto}")
    with socket.create_connection((host, puerto), timeout=10) as s:
        s.sendall(trama)
        print(f"[Replay] respuesta del servidor: {s.makefile('rb').readline().decode().strip()}")


if __name__ == "__main__":
    main()
