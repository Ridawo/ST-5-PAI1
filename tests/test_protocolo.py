# Tests del protocolo: firma canónica, verificación de MAC y tramas mal formadas.
# Ejecutar desde la raíz: python -m unittest discover tests -v
import io
import json
import unittest

from comun.protocolo import MAX_FRAME, canonical, derive_key, recv_frame, sign, verify_mac

CLAVE = b"k" * 32


class TestProtocolo(unittest.TestCase):
    def test_canonica_no_depende_del_orden(self):
        self.assertEqual(canonical({"a": 1, "b": {"y": 2, "x": 3}}), canonical({"b": {"x": 3, "y": 2}, "a": 1}))

    def test_canonica_ignora_el_campo_hmac(self):
        self.assertEqual(canonical({"a": 1}), canonical({"a": 1, "hmac": "lo que sea"}))

    def test_firma_valida(self):
        msg = sign({"action": "TRANSFER", "payload": {"amount": 10.5}}, CLAVE)
        self.assertEqual(len(msg["hmac"]), 64)  # 256 bits en hexadecimal
        self.assertTrue(verify_mac(msg, CLAVE))

    def test_firma_valida_tras_viajar_como_json(self):
        msg = json.loads(json.dumps(sign({"payload": {"amount": 1500.5}}, CLAVE)))
        self.assertTrue(verify_mac(msg, CLAVE))

    def test_mensaje_alterado_no_verifica(self):
        msg = sign({"payload": {"amount": 10}}, CLAVE)
        msg["payload"]["amount"] = 1000
        self.assertFalse(verify_mac(msg, CLAVE))

    def test_nonce_o_timestamp_alterados_no_verifican(self):
        for campo, valor in (("nonce", "00" * 16), ("timestamp", 0)):
            msg = sign({"a": 1}, CLAVE)
            msg[campo] = valor
            self.assertFalse(verify_mac(msg, CLAVE), campo)

    def test_clave_distinta_no_verifica(self):
        self.assertFalse(verify_mac(sign({"a": 1}, CLAVE), b"z" * 32))

    def test_hmac_ausente_o_raro_no_verifica(self):
        msg = sign({"a": 1}, CLAVE)
        for valor in (None, "", "ñ" * 64, 12345, ["x"]):
            msg["hmac"] = valor
            self.assertFalse(verify_mac(msg, CLAVE))

    def test_nonces_distintos(self):
        self.assertNotEqual(sign({}, CLAVE)["nonce"], sign({}, CLAVE)["nonce"])

    def test_derivacion_con_salt(self):
        k = derive_key("secreto123", b"s" * 16)
        self.assertEqual(len(k), 32)
        self.assertEqual(k, derive_key("secreto123", b"s" * 16))
        self.assertNotEqual(k, derive_key("secreto123", b"t" * 16))  # mismo password, otro salt -> otra clave

    def test_tramas_mal_formadas(self):
        for basura in (b"esto no es json\n", b"[1,2,3]\n", b'"texto"\n', b"{" * (MAX_FRAME + 10)):
            with self.assertRaises(ValueError):
                recv_frame(io.BytesIO(basura))

    def test_conexion_cerrada(self):
        self.assertIsNone(recv_frame(io.BytesIO(b"")))


if __name__ == "__main__":
    unittest.main()
