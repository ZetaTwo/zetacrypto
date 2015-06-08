__author__ = 'Calle'
import unittest

from zetacrypt import conversions


class TestConversionFunctions(unittest.TestCase):
    ASCII_TEST = "ABCD"
    HEX_TEST = "41424344"
    BYTE_TEST = b"ABCD"

    def test_hex_to_bytes(self):
        self.assertEqual(self.BYTE_TEST, conversions.hex_to_bytes(self.HEX_TEST))

    def test_bytes_to_hex(self):
        self.assertEqual(self.HEX_TEST, conversions.bytes_to_hex(self.BYTE_TEST))

    def test_ascii_to_bytes(self):
        self.assertEqual(self.BYTE_TEST, conversions.ascii_to_bytes(self.ASCII_TEST))

    def test_bytes_to_ascii(self):
        self.assertEqual(self.ASCII_TEST, conversions.bytes_to_ascii(self.BYTE_TEST))

    def test_base64_to_bytes(self):
        plaintext = "abcde"
        base64 = "YWJjZGU="
        self.assertEqual(conversions.ascii_to_bytes(plaintext), conversions.base64_to_bytes(base64))

    def test_bytes_to_base64(self):
        plaintext = "abcde"
        plaintext = conversions.ascii_to_bytes(plaintext)
        base64 = "YWJjZGU="
        self.assertEqual(base64, conversions.bytes_to_base64(plaintext))

if __name__ == '__main__':
    unittest.main()
