# Tests de seguridad: MAC alterado, nonce repetido, timestamp caducado, bloqueo por intentos, usuario duplicado.
# Ejecutar desde la raíz: python -m unittest discover tests -v
# Arrancan un servidor de verdad en un puerto libre con una BD temporal y hablan con él por TCP.
# Las líneas "[srv]" que salen con -v son el log del servidor.
import hmac
import logging
import os
import socketserver
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from contextlib import closing
from unittest import mock

from cliente import generador
from cliente.conexion import Conexion
from comun.protocolo import TIME_WINDOW, canonical, mac, sign, verify_mac
from servidor import datos, negocio, validacion
from servidor.conexion import Manejador

ORIGEN, DESTINO = "ES1234567890123456789012", "ES9876543210987654321098"


# Prints de narración. Van a stderr (como el log del servidor) para que salgan en el orden real.
def paso(msg):
    print(f"    · {msg}", file=sys.stderr, flush=True)


def ok(msg):
    print(f"    ✓ {msg}", file=sys.stderr, flush=True)


class TestSeguridad(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Saca por consola lo que el servidor va registrando durante los tests
        # (conexión, login OK/FALLIDO, TRANSFER, integridad...). force=True por si
        # otro test ya había tocado la config del logging.
        logging.basicConfig(level=logging.INFO, format="    [srv] %(levelname)-7s %(message)s", force=True)
        cls.tmp = tempfile.mkdtemp()
        cls.db = os.path.join(cls.tmp, "test.db")
        datos.init(cls.db, os.path.join(cls.tmp, "test.key"))
        negocio.sembrar()
        cls.srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Manejador)  # puerto 0 = uno libre
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def shortDescription(self):
        return None  # que unittest no repita el docstring: ya lo imprime nuestra cabecera

    def setUp(self):
        # Cabecera de cada test a partir de su docstring: qué se prueba y qué se espera.
        doc = (self._testMethodDoc or "").strip()
        print("\n" + "═" * 74, file=sys.stderr)
        print(f"▶ {self._testMethodName}", file=sys.stderr)
        for linea in doc.splitlines():
            print(f"  {linea.strip()}", file=sys.stderr)
        print("─" * 74, file=sys.stderr, flush=True)
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
        """RF1a / RF1c: registro de usuario y rechazo de duplicados.
        Esperado: el primer registro es OK; repetir el mismo usuario da 'ya existe'."""
        paso("registro de 'dave' por primera vez")
        r1 = self.con.pedir(generador.registro("dave", "dave12345"))
        self.assertEqual(r1["status"], "OK")
        ok(f"status = {r1['status']}")
        paso("intento de registrar 'dave' otra vez")
        resp = self.con.pedir(generador.registro("dave", "otra12345"))
        self.assertIn("ya existe", resp["reason"])
        ok(f"rechazado: {resp['reason']}")

    def test_password_guardada_con_salt_y_no_en_claro(self):
        """RS1a: las contraseñas nunca se guardan en claro: se derivan con PBKDF2 y salt.
        Esperado: cada usuario con su propio salt y una clave de 32 bytes; la contraseña no aparece."""
        with closing(sqlite3.connect(self.db)) as bd:
            filas = bd.execute("SELECT salt, key FROM users").fetchall()
        paso(f"leídas {len(filas)} filas de la tabla users directamente de SQLite")
        self.assertEqual(len({s for s, _ in filas}), len(filas))  # cada usuario con su propio salt
        ok(f"{len({s for s, _ in filas})} salts distintos para {len(filas)} usuarios (cada uno el suyo)")
        self.assertTrue(all(len(k) == 32 and b"alice1234" not in k for _, k in filas))
        ok("cada clave son 32 bytes derivados (PBKDF2) y no contienen la contraseña en claro")

    def test_login_correcto_con_respuesta_firmada(self):
        """RF1, RS2: login correcto y la respuesta del servidor llega firmada.
        Esperado: status OK y el HMAC de la respuesta verifica con la clave de sesión."""
        paso("alice hace LOGIN_INIT + LOGIN con su contraseña correcta")
        resp, clave = self.login()
        self.assertEqual(resp["status"], "OK")
        ok(f"login {resp['status']}, session_id = {resp['session_id'][:12]}…")
        self.assertTrue(verify_mac(resp, clave))
        ok("la respuesta trae un HMAC válido con la clave de sesión (un OK no se puede falsificar)")

    def test_login_mal_y_usuario_inexistente(self):
        """RS1: contraseña incorrecta y usuario inexistente se rechazan con el mismo mensaje.
        Esperado: 'credenciales incorrectas' en ambos casos (no se filtra si el usuario existe)."""
        paso("login de alice con contraseña incorrecta")
        r1 = self.login(password="mala12345")[0]["reason"]
        self.assertIn("incorrectas", r1)
        ok(f"rechazado: {r1}")
        paso("login de un usuario que no existe")
        r2 = self.login(usuario="nadie", password="nadie1234")[0]["reason"]
        self.assertIn("incorrectas", r2)
        ok(f"rechazado: {r2} (mismo mensaje: no se revela si el usuario existe)")

    def test_bloqueo_tras_5_fallos(self):
        """RS1b: 5 contraseñas incorrectas seguidas bloquean la cuenta.
        Esperado: tras MAX_FALLOS fallos, ni con la contraseña correcta se puede entrar."""
        self.con.pedir(generador.registro("eve", "eve123456"))
        paso(f"'eve' registrada; se falla el login {negocio.MAX_FALLOS} veces seguidas")
        for _ in range(negocio.MAX_FALLOS):
            self.assertIn("incorrectas", self.login("eve", "mala12345")[0]["reason"])
        ok(f"tras {negocio.MAX_FALLOS} fallos la cuenta queda bloqueada")
        paso("ahora se intenta con la contraseña CORRECTA")
        resp, _ = self.login("eve", "eve123456")  # ahora con la buena: sigue bloqueado
        self.assertIn("bloqueado", resp["reason"])
        ok(f"aun así se rechaza: {resp['reason']}")

    def test_bloqueo_usuario_inexistente(self):
        """RS1b: un usuario que no existe también se 'bloquea' tras 5 fallos, como uno real.
        Esperado: el mismo patrón de respuestas, así el bloqueo no delata qué usuarios existen."""
        def intento():  # sin PBKDF2: con un usuario inexistente da igual la prueba que se mande
            self.con.pedir(generador.login_init("fantasma"))
            return self.con.pedir({"action": "LOGIN", "username": "fantasma",
                                   "client_nonce": "00" * 16, "proof": "00" * 32})["reason"]
        paso(f"se falla el login {negocio.MAX_FALLOS} veces con 'fantasma', que no existe")
        for _ in range(negocio.MAX_FALLOS):
            self.assertIn("incorrectas", intento())
        motivo = intento()
        self.assertIn("bloqueado", motivo)
        ok(f"al sexto intento: {motivo} (igual que con una cuenta real)")

    def test_login_sin_reto(self):
        """Protocolo: no se puede hacer LOGIN sin pedir antes LOGIN_INIT (el reto del servidor).
        Esperado: el servidor exige LOGIN_INIT previo."""
        paso("se envía un LOGIN con un reto inventado, sin pedir LOGIN_INIT")
        msg, _ = generador.login("alice", "alice1234", "00" * 16, "00" * 16)
        resp = self.con.pedir(msg)
        self.assertIn("LOGIN_INIT", resp["reason"])
        ok(f"rechazado: {resp['reason']}")

    # ---------- RS2: integridad y autenticidad ----------

    def test_transferencia_correcta(self):
        """RF2: una transferencia bien formada y firmada se acepta y responde firmada.
        Esperado: status OK, tx_id que coincide y respuesta con HMAC válido."""
        sid, clave = self.sesion()
        paso("alice, ya con sesión, firma y envía una TRANSFER de 1500.50 EUR")
        msg = generador.transferencia(sid, clave, ORIGEN, DESTINO, 1500.50)
        resp = self.con.pedir(msg)
        self.assertEqual(resp["status"], "OK")
        self.assertEqual(resp["tx_id"], msg["payload"]["tx_id"])
        ok(f"aceptada, tx_id = {resp['tx_id']}")
        self.assertTrue(verify_mac(resp, clave))
        ok("la confirmación viene firmada con la clave de sesión")

    def test_mitm_importe_alterado(self):
        """RS2 (MitM): cambiar el importe de una TRANSFER ya firmada rompe el HMAC.
        Esperado: el servidor detecta la alteración y responde 'MAC inválido'."""
        sid, clave = self.sesion()
        msg = generador.transferencia(sid, clave, ORIGEN, DESTINO, 200)
        paso("alice firma una TRANSFER de 200 EUR")
        msg["payload"]["amount"] = 20000
        paso("el atacante cambia amount 200 -> 20000 (no puede recalcular el HMAC sin la clave)")
        resp = self.con.pedir(msg)
        self.assertIn("MAC inválido", resp["reason"])
        ok(f"servidor: {resp['reason']}")

    def test_mitm_mac_falsificado(self):
        """RS2: falsificar el HMAC con otra clave tampoco cuela.
        Esperado: como la clave del atacante no es la de sesión, el MAC no verifica."""
        sid, clave = self.sesion()
        msg = generador.transferencia(sid, clave, ORIGEN, DESTINO, 200)
        paso("el atacante reescribe el HMAC calculándolo con SU propia clave")
        msg["hmac"] = mac(b"clave del atacante" * 2, canonical(msg)).hex()
        resp = self.con.pedir(msg)
        self.assertIn("MAC inválido", resp["reason"])
        ok(f"servidor: {resp['reason']}")

    def test_transaccion_con_datos_invalidos(self):
        """RF2: validación de datos de la transferencia.
        Esperado: rechazo con IBAN mal formado, importe negativo, más de 2 decimales u origen=destino."""
        sid, clave = self.sesion()
        casos = {
            ("ES12", 10): "IBAN de origen mal formado",
            (ORIGEN, -5): "importe negativo",
            (ORIGEN, 1.234): "más de 2 decimales",
            (DESTINO, 10): "origen igual al destino",
        }
        for (origen, importe), motivo in casos.items():
            paso(f"caso: {motivo} (origen={origen!r}, importe={importe})")
            resp = self.con.pedir(generador.transferencia(sid, clave, origen, DESTINO, importe))
            self.assertEqual(resp["status"], "ERROR", (origen, importe))
            ok(f"rechazado: {resp['reason']}")

    def test_tx_id_no_canonico_se_rechaza(self):
        """RF2: el tx_id solo vale en forma canónica: el mismo UUID escrito de otra forma no es otra transacción.
        Esperado: tx_id en mayúsculas, entre llaves, con 'urn:uuid:' o sin guiones se rechaza por el tx_id."""
        sid, clave = self.sesion()
        msg = generador.transferencia(sid, clave, ORIGEN, DESTINO, 10)
        paso("alice hace una TRANSFER de 10 EUR")
        self.assertEqual(self.con.pedir(msg)["status"], "OK")
        tx_id = msg["payload"]["tx_id"]
        ok(f"aceptada, tx_id = {tx_id}")
        cuerpo = {k: v for k, v in msg.items() if k not in ("nonce", "timestamp", "hmac")}
        for variante in (tx_id.upper(), "{" + tx_id + "}", "urn:uuid:" + tx_id, tx_id.replace("-", "")):
            paso(f"la misma TRANSFER con tx_id = {variante!r}, nonce nuevo y bien firmada")
            resp = self.con.pedir(sign({**cuerpo, "payload": dict(msg["payload"], tx_id=variante)}, clave))
            self.assertEqual(resp["status"], "ERROR", variante)
            self.assertIn("UUIDv4", resp["reason"])
            ok(f"rechazado: {resp['reason']}")

    # ---------- RS3: replay ----------

    def test_replay_nonce_repetido(self):
        """RS3: reenviar una TRANSFER válida (ataque de replay) se detecta por el nonce repetido.
        Esperado: la primera pasa; la copia reenviada da 'nonce repetido'."""
        sid, clave = self.sesion()
        msg = generador.transferencia(sid, clave, ORIGEN, DESTINO, 50)
        paso("alice hace una TRANSFER de 50 EUR")
        self.assertEqual(self.con.pedir(msg)["status"], "OK")
        ok("la primera se acepta")
        paso("el atacante reenvía EXACTAMENTE la misma trama desde otra conexión")
        otra = Conexion(*self.srv.server_address)  # el atacante reenvía desde otra conexión
        resp = otra.pedir(msg)
        self.assertIn("nonce repetido", resp["reason"])
        ok(f"servidor: {resp['reason']}")
        otra.cerrar()

    def firmada_con_desfase(self, sid, clave, desfase):
        """TRANSFER bien firmada pero con el timestamp movido 'desfase' segundos."""
        msg = generador.transferencia(sid, clave, ORIGEN, DESTINO, 50)
        msg["timestamp"] = int(time.time()) + desfase
        msg["hmac"] = mac(clave, canonical(msg)).hex()
        return msg

    def test_replay_timestamp_caducado(self):
        """RS3: un mensaje fuera de la ventana de TIME_WINDOW s se rechaza aunque esté bien firmado.
        Esperado: 'timestamp fuera de la ventana' si es de hace 5 min y también si viene 5 min del futuro."""
        sid, clave = self.sesion()
        for desfase in (-300, 300):
            paso(f"TRANSFER con timestamp {desfase:+d} s, vuelta a firmar bien")
            resp = self.con.pedir(self.firmada_con_desfase(sid, clave, desfase))
            self.assertIn("timestamp", resp["reason"])
            ok(f"servidor: {resp['reason']}")

    def test_timestamp_dentro_de_la_ventana_se_acepta(self):
        """RS3: la ventana tolera relojes desfasados hasta TIME_WINDOW segundos.
        Esperado: un mensaje 20 s dentro del límite, atrasado o adelantado, se acepta."""
        sid, clave = self.sesion()
        for desfase in (-(TIME_WINDOW - 20), TIME_WINDOW - 20):
            paso(f"TRANSFER con timestamp {desfase:+d} s (dentro de ±{TIME_WINDOW} s)")
            resp = self.con.pedir(self.firmada_con_desfase(sid, clave, desfase))
            self.assertEqual(resp["status"], "OK", resp.get("reason"))
            ok("aceptada")

    def test_nonces_antiguos_se_borran(self):
        """RS3: la tabla de nonces no crece sin fin: los de más de 2 ventanas se borran solos.
        Esperado: al registrar un nonce nuevo desaparece uno de justo antes del límite y se conserva uno posterior."""
        viejo, reciente = 2 * TIME_WINDOW + 5, 2 * TIME_WINDOW - 40
        with closing(sqlite3.connect(self.db)) as bd, bd:
            bd.executemany("INSERT INTO nonces VALUES (?,?)", [("nonce-viejo", time.time() - viejo),
                                                              ("nonce-reciente", time.time() - reciente)])
        paso(f"se meten en la BD un nonce de hace {viejo} s y otro de hace {reciente} s; luego llega uno nuevo")
        self.assertTrue(datos.registrar_nonce("nonce-nuevo"))
        with closing(sqlite3.connect(self.db)) as bd:
            quedan = {n for (n,) in bd.execute("SELECT nonce FROM nonces WHERE nonce IN ('nonce-viejo', 'nonce-reciente')")}
        self.assertEqual(quedan, {"nonce-reciente"})
        ok("el viejo se ha borrado y el reciente sigue (aún podría servir para un replay)")

    # ---------- RS4: tiempo constante ----------

    def test_comparaciones_en_tiempo_constante(self):
        """RS4: en el servidor, la prueba de login y las firmas de filas se comparan con compare_digest.
        Esperado: las dos comprobaciones llaman a hmac.compare_digest (verify_mac lo prueba test_protocolo)."""
        paso("se espía hmac.compare_digest y se llama a comprobar_prueba_login y a fila_integra")
        with mock.patch("hmac.compare_digest", wraps=hmac.compare_digest) as espia:
            validacion.comprobar_prueba_login(b"k" * 32, b"s" * 16, b"c" * 16, "00" * 32)
            datos.fila_integra("00" * 32, "alice")
        self.assertEqual(espia.call_count, 2)
        ok("las dos comparaciones de secretos pasan por compare_digest")

    # ---------- sesiones ----------

    def test_logout_invalida_la_sesion(self):
        """RF1d: tras LOGOUT la sesión deja de valer.
        Esperado: el logout es OK y transferir después con esa sesión se rechaza."""
        sid, clave = self.sesion()
        paso("alice inicia sesión y hace LOGOUT")
        self.assertEqual(self.con.pedir(generador.logout(sid, clave))["status"], "OK")
        ok("logout OK")
        paso("intenta transferir con la sesión ya cerrada")
        resp = self.con.pedir(generador.transferencia(sid, clave, ORIGEN, DESTINO, 10))
        self.assertIn("sesión no válida", resp["reason"])
        ok(f"rechazado: {resp['reason']}")

    def test_sesion_inventada(self):
        """RF1d: una session_id inventada no permite operar.
        Esperado: 'sesión no válida o caducada'."""
        paso("se transfiere con una session_id y una clave inventadas de la nada")
        resp = self.con.pedir(generador.transferencia("ab" * 32, b"x" * 32, ORIGEN, DESTINO, 10))
        self.assertIn("sesión no válida", resp["reason"])
        ok(f"rechazado: {resp['reason']}")

    # ---------- robustez ----------

    def test_trama_mal_formada_no_tumba_el_servidor(self):
        """Robustez: enviar basura por el socket no tumba el servidor.
        Esperado: cada trama inválida devuelve un ERROR y la conexión sigue viva."""
        s = self.con.sock
        for basura in (b"no soy json\n", b"[1,2]\n", b'{"action": "TRANSFER"}\n', b'{"action": 5}\n'):
            paso(f"se envía basura: {basura!r}")
            s.sendall(basura)
            self.assertEqual(self.con.rfile.readline().count(b"ERROR"), 1)
            ok("respondió 1 ERROR sin caerse")
        self.assertEqual(self.login()[0]["status"], "OK")  # la conexión sigue viva
        ok("tras toda la basura, un login normal sigue funcionando")

    # ---------- integridad de lo almacenado ----------

    def test_manipular_la_bd_se_detecta(self):
        """Integridad de la BD: tocar un importe directamente en la BD se detecta.
        Esperado: filas_corruptas() está vacío al principio y señala la fila tras manipularla."""
        sid, clave = self.sesion()
        msg = generador.transferencia(sid, clave, ORIGEN, DESTINO, 75)
        self.con.pedir(msg)
        paso("alice hace una TRANSFER de 75 EUR (queda firmada en la BD)")
        self.assertEqual(datos.filas_corruptas(), [])
        ok("filas_corruptas() = [] (todo íntegro)")
        paso("un atacante con acceso a la BD cambia amount 75 -> 75000 saltándose al servidor")
        with sqlite3.connect(self.db) as bd:
            bd.execute("UPDATE transactions SET amount = 75000 WHERE tx_id = ?", (msg["payload"]["tx_id"],))
        corruptas = datos.filas_corruptas()
        self.assertEqual(corruptas, [f"transactions/{msg['payload']['tx_id']}"])
        ok(f"detectado al comprobar la firma de la fila: {corruptas}")
        with sqlite3.connect(self.db) as bd:  # se deja como estaba
            bd.execute("UPDATE transactions SET amount = 75 WHERE tx_id = ?", (msg["payload"]["tx_id"],))

    def test_manipular_bloqueo_se_detecta(self):
        """RS1b: el contador de fallos y el bloqueo también van firmados en la BD.
        Esperado: 'desbloquear' una cuenta editando la BD a mano se detecta como manipulación."""
        self.con.pedir(generador.registro("frank", "frank1234"))
        paso("'frank' registrado; su fila está íntegra")
        self.assertNotIn("users/frank", datos.filas_corruptas())
        paso("un atacante pone failed=99, locked_until=0 en la BD para 'desbloquear' a mano")
        with sqlite3.connect(self.db) as bd:
            bd.execute("UPDATE users SET failed = 99, locked_until = 0 WHERE username = 'frank'")
        self.assertIn("users/frank", datos.filas_corruptas())
        ok("detectado: la fila users/frank aparece como manipulada")
        with sqlite3.connect(self.db) as bd:  # se deja como estaba
            bd.execute("UPDATE users SET failed = 0 WHERE username = 'frank'")


if __name__ == "__main__":
    unittest.main()
