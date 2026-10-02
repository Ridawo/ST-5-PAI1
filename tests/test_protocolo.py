# Tests del protocolo: firma canónica, verificación de MAC y tramas mal formadas.
# Ejecutar desde la raíz: python -m unittest discover tests -v
import hmac
import io
import json
import sys
import unittest
from unittest import mock

from comun.protocolo import (
    MAX_FRAME,
    canonical,
    derive_key,
    recv_frame,
    sign,
    verify_mac,
)

CLAVE = b"k" * 32


def paso(msg):
    print(f"    · {msg}", file=sys.stderr, flush=True)


def ok(msg):
    print(f"    ✓ {msg}", file=sys.stderr, flush=True)


class TestProtocolo(unittest.TestCase):
    def shortDescription(self):
        return None  # que unittest no repita el docstring: ya lo imprime nuestra cabecera

    def setUp(self):
        doc = (self._testMethodDoc or "").strip()
        print("\n" + "═" * 74, file=sys.stderr)
        print(f"▶ {self._testMethodName}", file=sys.stderr)
        for linea in doc.splitlines():
            print(f"  {linea.strip()}", file=sys.stderr)
        print("─" * 74, file=sys.stderr, flush=True)

    def test_canonica_no_depende_del_orden(self):
        """La forma canónica (lo que se firma) no depende del orden de las claves del JSON.
        Esperado: dos mensajes con los mismos datos en distinto orden dan los mismos bytes."""
        paso("se canonizan dos dicts iguales con las claves en distinto orden")
        self.assertEqual(canonical({"a": 1, "b": {"y": 2, "x": 3}}), canonical({"b": {"x": 3, "y": 2}, "a": 1}))
        ok("mismos bytes -> la firma no se rompe por el orden del JSON")

    def test_canonica_ignora_el_campo_hmac(self):
        """El propio campo 'hmac' no entra en lo que se firma (si no, sería imposible firmar).
        Esperado: añadir 'hmac' no cambia la forma canónica."""
        paso("se compara la canónica con y sin el campo 'hmac'")
        self.assertEqual(canonical({"a": 1}), canonical({"a": 1, "hmac": "lo que sea"}))
        ok("el campo 'hmac' se excluye de la firma")

    def test_firma_valida(self):
        """sign() añade un HMAC de 256 bits que verify_mac() acepta con la misma clave.
        Esperado: HMAC de 64 hex y verificación correcta."""
        msg = sign({"action": "TRANSFER", "payload": {"amount": 10.5}}, CLAVE)
        paso(f"mensaje firmado, hmac = {msg['hmac'][:16]}… ({len(msg['hmac'])} hex)")
        self.assertEqual(len(msg["hmac"]), 64)  # 256 bits en hexadecimal
        self.assertTrue(verify_mac(msg, CLAVE))
        ok("verify_mac() lo acepta con la misma clave")

    def test_firma_valida_tras_viajar_como_json(self):
        """La firma sigue valiendo después de serializar y volver a parsear el mensaje.
        Esperado: verifica igual tras el viaje por json.dumps/loads (como en el socket real)."""
        paso("se firma, se pasa a texto JSON y se vuelve a parsear (como al enviar por el socket)")
        msg = json.loads(json.dumps(sign({"payload": {"amount": 1500.5}}, CLAVE)))
        self.assertTrue(verify_mac(msg, CLAVE))
        ok("sigue verificando tras el ida y vuelta a JSON")

    def test_mensaje_alterado_no_verifica(self):
        """Cambiar un dato tras firmar invalida el HMAC (integridad).
        Esperado: tras cambiar amount 10 -> 1000, verify_mac falla."""
        msg = sign({"payload": {"amount": 10}}, CLAVE)
        paso("se altera amount 10 -> 1000 después de firmar")
        msg["payload"]["amount"] = 1000
        self.assertFalse(verify_mac(msg, CLAVE))
        ok("verify_mac() lo rechaza: el mensaje fue alterado")

    def test_nonce_o_timestamp_alterados_no_verifican(self):
        """El nonce y el timestamp entran en la firma (principio de Horton).
        Esperado: tocar cualquiera de los dos rompe la verificación."""
        for campo, valor in (("nonce", "00" * 16), ("timestamp", 0)):
            msg = sign({"a": 1}, CLAVE)
            paso(f"se cambia el campo '{campo}' tras firmar")
            msg[campo] = valor
            self.assertFalse(verify_mac(msg, CLAVE), campo)
            ok(f"verify_mac() falla al tocar '{campo}'")

    def test_clave_distinta_no_verifica(self):
        """Sin la clave correcta no se puede validar la firma (autenticidad).
        Esperado: verificar con otra clave falla."""
        paso("se firma con una clave y se verifica con otra distinta")
        self.assertFalse(verify_mac(sign({"a": 1}, CLAVE), b"z" * 32))
        ok("verify_mac() falla con la clave equivocada")

    def test_hmac_ausente_o_raro_no_verifica(self):
        """Un HMAC ausente o con un valor extraño no debe colar ni provocar un error.
        Esperado: verify_mac devuelve False para None, vacío, no-hex, número o lista."""
        msg = sign({"a": 1}, CLAVE)
        for valor in (None, "", "ñ" * 64, 12345, ["x"]):
            paso(f"hmac = {valor!r}")
            msg["hmac"] = valor
            self.assertFalse(verify_mac(msg, CLAVE))
            ok("rechazado sin romperse")

    def test_verify_mac_usa_compare_digest(self):
        """RS4: verify_mac compara las firmas con hmac.compare_digest (tiempo constante), nunca con ==.
        Esperado: compare_digest se llama una vez en cada verificación, acierte o falle."""
        msg = sign({"a": 1}, CLAVE)
        paso("se espía hmac.compare_digest y se verifica un mensaje con la clave buena y con una mala")
        with mock.patch("hmac.compare_digest", wraps=hmac.compare_digest) as espia:
            self.assertTrue(verify_mac(msg, CLAVE))
            self.assertFalse(verify_mac(msg, b"z" * 32))
        self.assertEqual(espia.call_count, 2)
        ok("las dos comparaciones pasan por compare_digest")

    def test_nonces_distintos(self):
        """Cada firma genera un nonce nuevo (no se repiten).
        Esperado: dos firmas seguidas tienen nonces distintos."""
        paso("se firman dos mensajes y se comparan sus nonces")
        self.assertNotEqual(sign({}, CLAVE)["nonce"], sign({}, CLAVE)["nonce"])
        ok("nonces distintos en cada firma")

    def test_derivacion_con_salt(self):
        """RS1a: derive_key (PBKDF2) da una clave de 32 bytes, determinista por (password, salt).
        Esperado: misma entrada -> misma clave; mismo password con otro salt -> otra clave."""
        k = derive_key("secreto123", b"s" * 16)
        paso(f"clave derivada de ('secreto123', salt 's') -> {len(k)} bytes")
        self.assertEqual(len(k), 32)
        self.assertEqual(k, derive_key("secreto123", b"s" * 16))
        ok("misma contraseña y mismo salt -> misma clave (determinista)")
        self.assertNotEqual(k, derive_key("secreto123", b"t" * 16))  # mismo password, otro salt -> otra clave
        ok("misma contraseña con otro salt -> clave distinta")

    def test_tramas_mal_formadas(self):
        """recv_frame rechaza lo que no es un objeto JSON válido.
        Esperado: lanza ValueError con basura, listas o texto suelto."""
        for basura in (b"esto no es json\n", b"[1,2,3]\n", b'"texto"\n'):
            paso(f"recv_frame con: {basura[:24]!r}{'…' if len(basura) > 24 else ''}")
            with self.assertRaises(ValueError):
                recv_frame(io.BytesIO(basura))
            ok("lanza ValueError (trama descartada)")

    def test_trama_gigante_se_descarta_entera(self):
        """Una trama de más de MAX_FRAME bytes se rechaza aunque sea JSON válido, y se tira entera.
        Esperado: ValueError, y la trama siguiente se lee bien (el resto no se cuela como tramas nuevas)."""
        gigante = b'{"a":"' + b"x" * (3 * MAX_FRAME) + b'"}\n'
        flujo = io.BytesIO(gigante + b'{"b":1}\n')
        paso(f"llega un JSON válido de {len(gigante)} bytes (máximo {MAX_FRAME}) y detrás uno normal")
        with self.assertRaises(ValueError):
            recv_frame(flujo)
        ok("la trama gigante lanza ValueError")
        self.assertEqual(recv_frame(flujo), {"b": 1})
        ok("la siguiente trama se lee entera: no hay desincronización")

    def test_conexion_cerrada(self):
        """recv_frame devuelve None cuando el otro extremo cierra la conexión.
        Esperado: None ante una entrada vacía."""
        paso("recv_frame sobre un flujo vacío (el otro lado cerró)")
        self.assertIsNone(recv_frame(io.BytesIO(b"")))
        ok("devuelve None sin error")


if __name__ == "__main__":
    unittest.main()
