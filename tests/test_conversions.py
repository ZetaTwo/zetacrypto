__author__ = 'Calle Svensson <calle.svensson@zeta-two.com>'
from builtins import bytes, str, filter, map
import unittest

from zetacrypt import conversions


class TestConversionFunctions(unittest.TestCase):
    ASCII_TEST = "ABCD"
    HEX_TEST = "41424344"
    BYTE_TEST = conversions.ascii_to_bytes("ABCD")

    def test_hex_to_bytes(self):
        res = conversions.hex_to_bytes(self.HEX_TEST)
        self.assertEqual(type(res), bytes)
        self.assertEqual(self.BYTE_TEST, res)

    def test_bytes_to_hex(self):
        res = conversions.bytes_to_hex(self.BYTE_TEST)
        self.assertEqual(type(res), str)
        self.assertEqual(self.HEX_TEST, res)

    def test_ascii_to_bytes(self):
        res = conversions.ascii_to_bytes(self.ASCII_TEST)
        self.assertEqual(type(res), bytes)
        self.assertEqual(self.BYTE_TEST, res)

    def test_bytes_to_ascii(self):
        res = conversions.bytes_to_ascii(self.BYTE_TEST)
        self.assertEqual(type(res), str)
        self.assertEqual(self.ASCII_TEST, res)

    def test_base64_to_bytes(self):
        plaintext = "abcde"
        base64 = "YWJjZGU="
        res = conversions.base64_to_bytes(base64)
        self.assertEqual(type(res), bytes)
        self.assertEqual(conversions.ascii_to_bytes(plaintext), res)

    def test_bytes_to_base64(self):
        plaintext = "abcde"
        plaintext = conversions.ascii_to_bytes(plaintext)
        base64 = "YWJjZGU="

        res = conversions.bytes_to_base64(plaintext)
        self.assertEqual(type(res), str)
        self.assertEqual(base64, res)

    def test_iterator_to_bytes(self):
        plaintext = "abcde"
        mapped = conversions.ascii_to_bytes(plaintext)
        flattened = conversions.iterator_to_bytes(mapped)
        self.assertEqual(len(plaintext), len(flattened))
        self.assertEqual(plaintext, conversions.bytes_to_ascii(flattened))

if __name__ == '__main__':
    unittest.main()
