# Módulo de interfaz de usuario (UI): menú de registro, login, transferencia y logout.
"""
Uso (desde la raíz del repo, igual en Linux y Windows):
    python -m cliente.interfaz [host] [puerto]      por defecto 127.0.0.1 5000
Para pasar por el proxy MitM:  python -m cliente.interfaz 127.0.0.1 5001
"""
import getpass
import os
import sys

from cliente import generador
from cliente.conexion import Conexion
from comun.protocolo import verify_mac

ANCHO = 48
INTENTOS_LOGIN = 5  # los mismos que tolera el servidor antes de bloquear


def pantalla(usuario):
    os.system("cls" if os.name == "nt" else "clear")
    print("=" * ANCHO)
    print("SecBank · IntegriDos".center(ANCHO))
    print(f" Sesión: {usuario or 'sin iniciar'}")
    print("=" * ANCHO)


def respuesta_ok(resp, clave=None):
    """Un OK solo cuenta si viene firmado con la clave de sesión (si la hay)."""
    if resp.get("status") != "OK":
        print(f"\n [ERROR] {resp.get('reason')}")
        return False
    if clave and not verify_mac(resp, clave):
        print("\n [ALERTA] La respuesta dice OK pero su firma no es válida: posible manipulación")
        return False
    return True


def registrarse(con):
    usuario = input(" Usuario: ").strip()
    password = getpass.getpass(" Contraseña (mín. 8): ")
    if password != getpass.getpass(" Repite la contraseña: "):
        print("\n [ERROR] Las contraseñas no coinciden")
        return
    if respuesta_ok(con.pedir(generador.registro(usuario, password))):
        print("\n [OK] Usuario registrado, ya puedes iniciar sesión")


def iniciar_sesion(con):
    """Devuelve (usuario, session_id, clave_sesion) o None.
    Si la contraseña es incorrecta la vuelve a pedir, hasta INTENTOS_LOGIN veces
    (el servidor bloquea la cuenta al 5º fallo). Contraseña vacía = volver al menú."""
    usuario = input(" Usuario: ").strip()
    for intento in range(1, INTENTOS_LOGIN + 1):
        password = getpass.getpass(f" Contraseña (intento {intento}/{INTENTOS_LOGIN}, vacía para volver): ")
        if not password:
            return None
        reto = con.pedir(generador.login_init(usuario))  # cada intento necesita un reto nuevo
        if not respuesta_ok(reto):
            return None
        msg, clave = generador.login(usuario, password, reto["salt"], reto["server_nonce"])
        resp = con.pedir(msg)
        if respuesta_ok(resp, clave):
            print(f"\n [OK] Bienvenido/a, {usuario}")
            return usuario, resp["session_id"], clave
        if "incorrectas" not in str(resp.get("reason")):  # bloqueado u otro error: no tiene sentido reintentar
            return None
        print()
    return None


def transferir(con, sid, clave):
    origen = input(" Cuenta origen  (ES + 22 dígitos): ").strip().upper()
    destino = input(" Cuenta destino (ES + 22 dígitos): ").strip().upper()
    try:
        importe = round(float(input(" Importe en EUR: ").replace(",", ".")), 2)
    except ValueError:
        print("\n [ERROR] El importe tiene que ser un número")
        return
    msg = generador.transferencia(sid, clave, origen, destino, importe)
    resp = con.pedir(msg)
    if respuesta_ok(resp, clave) and resp.get("tx_id") == msg["payload"]["tx_id"]:
        print(f"\n [OK] Transferencia registrada\n      id: {resp['tx_id']}")


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    puerto = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    try:
        con = Conexion(host, puerto)
    except OSError as e:
        sys.exit(f"No se pudo conectar con {host}:{puerto} ({e}). ¿Está el servidor arrancado?")

    sesion = None  # (usuario, session_id, clave_sesion)
    try:
        while True:
            pantalla(sesion and sesion[0])
            if sesion is None:
                print(" 1) Registrarse\n 2) Iniciar sesión\n 0) Salir")
            else:
                print(" 1) Nueva transferencia\n 2) Cerrar sesión\n 0) Salir")
            op = input("\n > ").strip()
            if op == "0":
                break
            if sesion is None and op == "1":
                registrarse(con)
            elif sesion is None and op == "2":
                sesion = iniciar_sesion(con)
            elif sesion and op == "1":
                transferir(con, sesion[1], sesion[2])
            elif sesion and op == "2":
                if respuesta_ok(con.pedir(generador.logout(sesion[1], sesion[2])), sesion[2]):
                    print("\n [OK] Sesión cerrada")
                sesion = None
            else:
                continue
            input("\n Pulsa Enter para continuar...")
        if sesion:
            con.pedir(generador.logout(sesion[1], sesion[2]))
    except (KeyboardInterrupt, EOFError):
        print()
    except OSError as e:
        print(f"\n Se perdió la conexión con el servidor ({e})")
    finally:
        con.cerrar()


if __name__ == "__main__":
    main()
