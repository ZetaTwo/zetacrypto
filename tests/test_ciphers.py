__author__ = 'Calle'
import unittest

from zetacrypt import ciphers, conversions


class TestXORFunctions(unittest.TestCase):
    def test_single_byte_xor(self):
        plaintext = conversions.ascii_to_bytes("abcd")
        ciphertext = conversions.ascii_to_bytes("ABCD")
        key = ord(' ')
        self.assertEqual(ciphertext, bytes(ciphers.xor_seq_byte(plaintext, key)))

    def set1_problem2(self):
        """Set 1 problem 2"""
        ciphertext = conversions.hex_to_bytes("746865206b696420646f6e277420706c6179")
        key = conversions.hex_to_bytes("686974207468652062756c6c277320657965")
        plaintext = conversions.hex_to_bytes("1c0111001f010100061a024b53535009181c")
        self.assertEqual(ciphertext, ciphers.xor_seq_key(plaintext, key))

class TestPrepareFunctions(unittest.TestCase):
    def test_pkcs7(self):
        """Set 2 problem 1"""
        plaintext = conversions.ascii_to_bytes("YELLOW SUBMARINE")
        ciphertext = b"YELLOW SUBMARINE\x04\x04\x04\x04"
        c = ciphers.pkcs7(plaintext, 20)
        self.assertEqual(ciphertext, c)