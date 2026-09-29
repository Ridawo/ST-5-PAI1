# Tests de seguridad: MAC alterado, nonce repetido, timestamp caducado, bloqueo por intentos, usuario duplicado.
# Ejecutar desde la raíz: python -m unittest discover tests -v
# Arrancan un servidor de verdad en un puerto libre con una BD temporal y hablan con él por TCP.
import os
import socketserver
import sqlite3
import tempfile
import threading
import time
import unittest

from cliente import generador
from cliente.conexion import Conexion
from comun.protocolo import canonical, mac, verify_mac
from servidor import datos, negocio
from servidor.conexion import Manejador

ORIGEN, DESTINO = "ES1234567890123456789012", "ES9876543210987654321098"


class TestSeguridad(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        datos.init(os.path.join(cls.tmp, "test.db"), os.path.join(cls.tmp, "test.key"))
        negocio.sembrar()
        cls.srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Manejador)  # puerto 0 = uno libre
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        self.con = Conexion(*self.srv.server_address)

    def tearDown(self):
        self.con.cerrar()

    def login(self, usuario="alice", password="alice1234", con=None):
        con = con or self.con
        reto = con.pedir(generador.login_init(usuario))
        msg, clave = generador.login(usuario, password, reto["salt"], reto["server_nonce"])
        return con.pedir(msg), clave

    def sesion(self):
        resp, clave = self.login()
        self.assertEqual(resp["status"], "OK")
        return resp["session_id"], clave

    # ---------- RS1: credenciales ----------

    def test_registro_y_duplicado(self):
        self.assertEqual(self.con.pedir(generador.registro("dave", "dave12345"))["status"], "OK")
        resp = self.con.pedir(generador.registro("dave", "otra12345"))
        self.assertIn("ya existe", resp["reason"])

    def test_password_guardada_con_salt_y_no_en_claro(self):
        filas = sqlite3.connect(os.path.join(self.tmp, "test.db")).execute("SELECT salt, key FROM users").fetchall()
        self.assertEqual(len({s for s, _ in filas}), len(filas))  # cada usuario con su propio salt
        self.assertTrue(all(len(k) == 32 and b"alice1234" not in k for _, k in filas))

    def test_login_correcto_con_respuesta_firmada(self):
        resp, clave = self.login()
        self.assertEqual(resp["status"], "OK")
        self.assertTrue(verify_mac(resp, clave))

    def test_login_mal_y_usuario_inexistente(self):
        self.assertIn("incorrectas", self.login(password="mala12345")[0]["reason"])
        self.assertIn("incorrectas", self.login(usuario="nadie", password="nadie1234")[0]["reason"])

    def test_bloqueo_tras_5_fallos(self):
        self.con.pedir(generador.registro("eve", "eve123456"))
        for _ in range(negocio.MAX_FALLOS):
            self.assertIn("incorrectas", self.login("eve", "mala12345")[0]["reason"])
        resp, _ = self.login("eve", "eve123456")  # ahora con la buena: sigue bloqueado
        self.assertIn("bloqueado", resp["reason"])

    def test_login_sin_reto(self):
        msg, _ = generador.login("alice", "alice1234", "00" * 16, "00" * 16)
        self.assertIn("LOGIN_INIT", self.con.pedir(msg)["reason"])

    # ---------- RS2: integridad y autenticidad ----------

    def test_transferencia_correcta(self):
        sid, clave = self.sesion()
        msg = generador.transferencia(sid, clave, ORIGEN, DESTINO, 1500.50)
        resp = self.con.pedir(msg)
        self.assertEqual(resp["status"], "OK")
        self.assertEqual(resp["tx_id"], msg["payload"]["tx_id"])
        self.assertTrue(verify_mac(resp, clave))

    def test_mitm_importe_alterado(self):
        sid, clave = self.sesion()
        msg = generador.transferencia(sid, clave, ORIGEN, DESTINO, 200)
        msg["payload"]["amount"] = 20000
        self.assertIn("MAC inválido", self.con.pedir(msg)["reason"])

    def test_mitm_mac_falsificado(self):
        sid, clave = self.sesion()
        msg = generador.transferencia(sid, clave, ORIGEN, DESTINO, 200)
        msg["hmac"] = mac(b"clave del atacante" * 2, canonical(msg)).hex()
        self.assertIn("MAC inválido", self.con.pedir(msg)["reason"])

    def test_transaccion_con_datos_invalidos(self):
        sid, clave = self.sesion()
        for origen, importe in (("ES12", 10), (ORIGEN, -5), (ORIGEN, 1.234), (DESTINO, 10)):
            resp = self.con.pedir(generador.transferencia(sid, clave, origen, DESTINO, importe))
            self.assertEqual(resp["status"], "ERROR", (origen, importe))

    # ---------- RS3: replay ----------

    def test_replay_nonce_repetido(self):
        sid, clave = self.sesion()
        msg = generador.transferencia(sid, clave, ORIGEN, DESTINO, 50)
        self.assertEqual(self.con.pedir(msg)["status"], "OK")
        otra = Conexion(*self.srv.server_address)  # el atacante reenvía desde otra conexión
        self.assertIn("nonce repetido", otra.pedir(msg)["reason"])
        otra.cerrar()

    def test_replay_timestamp_caducado(self):
        sid, clave = self.sesion()
        msg = generador.transferencia(sid, clave, ORIGEN, DESTINO, 50)
        msg["timestamp"] = int(time.time()) - 300  # mensaje "viejo" pero bien firmado
        msg["hmac"] = mac(clave, canonical(msg)).hex()
        self.assertIn("timestamp", self.con.pedir(msg)["reason"])

    # ---------- sesiones ----------

    def test_logout_invalida_la_sesion(self):
        sid, clave = self.sesion()
        self.assertEqual(self.con.pedir(generador.logout(sid, clave))["status"], "OK")
        resp = self.con.pedir(generador.transferencia(sid, clave, ORIGEN, DESTINO, 10))
        self.assertIn("sesión no válida", resp["reason"])

    def test_sesion_inventada(self):
        resp = self.con.pedir(generador.transferencia("ab" * 32, b"x" * 32, ORIGEN, DESTINO, 10))
        self.assertIn("sesión no válida", resp["reason"])

    # ---------- robustez ----------

    def test_trama_mal_formada_no_tumba_el_servidor(self):
        s = self.con.sock
        for basura in (b"no soy json\n", b"[1,2]\n", b'{"action": "TRANSFER"}\n', b'{"action": 5}\n'):
            s.sendall(basura)
            self.assertEqual(self.con.rfile.readline().count(b"ERROR"), 1)
        self.assertEqual(self.login()[0]["status"], "OK")  # la conexión sigue viva

    # ---------- integridad de lo almacenado ----------

    def test_manipular_la_bd_se_detecta(self):
        sid, clave = self.sesion()
        msg = generador.transferencia(sid, clave, ORIGEN, DESTINO, 75)
        self.con.pedir(msg)
        self.assertEqual(datos.filas_corruptas(), [])
        with sqlite3.connect(os.path.join(self.tmp, "test.db")) as bd:
            bd.execute("UPDATE transactions SET amount = 75000 WHERE tx_id = ?", (msg["payload"]["tx_id"],))
        self.assertEqual(datos.filas_corruptas(), [f"transactions/{msg['payload']['tx_id']}"])
        with sqlite3.connect(os.path.join(self.tmp, "test.db")) as bd:  # se deja como estaba
            bd.execute("UPDATE transactions SET amount = 75 WHERE tx_id = ?", (msg["payload"]["tx_id"],))

    def test_manipular_bloqueo_se_detecta(self):
        # RS1b: el contador de fallos y el bloqueo también están firmados; tocarlos en la BD
        # (p. ej. para desbloquear una cuenta) se detecta como manipulación.
        self.con.pedir(generador.registro("frank", "frank1234"))
        self.assertNotIn("users/frank", datos.filas_corruptas())
        with sqlite3.connect(os.path.join(self.tmp, "test.db")) as bd:
            bd.execute("UPDATE users SET failed = 99, locked_until = 0 WHERE username = 'frank'")
        self.assertIn("users/frank", datos.filas_corruptas())
        with sqlite3.connect(os.path.join(self.tmp, "test.db")) as bd:  # se deja como estaba
            bd.execute("UPDATE users SET failed = 0 WHERE username = 'frank'")


if __name__ == "__main__":
    unittest.main()
