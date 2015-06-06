__author__ = 'Calle Svensson <calle.svensson@zeta-two.com>'
import unittest

from zetacrypt import cryptanalysis, conversions


class TestTextFunctions(unittest.TestCase):
    def test_count_printable(self):
        self.assertEqual(12, cryptanalysis.count_printable(" amzANZ019%/"))

    def test_is_printable1(self):
        self.assertTrue(cryptanalysis.is_printable(" amzANZ019%/"))

    def test_is_printable2(self):
        self.assertFalse(cryptanalysis.is_printable(" amzANZ019%/\x10"))


class TextXorFunctions(unittest.TestCase):
    def test_find_single_byte_xor_key(self):
        """Set 1 problem 3"""
        ciphertext = conversions.hex_to_bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
        plaintext = "Cooking MC's like a pound of bacon"
        key = 88

        m, k, _ = cryptanalysis.find_single_byte_xor_key(ciphertext)
        self.assertEqual(key, k)
        self.assertEqual(plaintext, m)


if __name__ == '__main__':
    unittest.main()
