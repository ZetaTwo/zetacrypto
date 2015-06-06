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

    def set1_problem1(self):
        """Set 1 problem 1"""
        input_ascii = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        target_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        self.assertEqual(target_hex, conversions.ascii_to_hex(input_ascii))


if __name__ == '__main__':
    unittest.main()
