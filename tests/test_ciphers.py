__author__ = 'Calle'
import unittest

from zetacrypt import ciphers, conversions, utility


class TestXORFunctions(unittest.TestCase):
    def test_single_byte_xor(self):
        plaintext = conversions.ascii_to_bytes("abcd")
        ciphertext = conversions.ascii_to_bytes("ABCD")
        key = ord(' ')
        self.assertEqual(ciphertext, bytes(ciphers.xor_seq_byte(plaintext, key)))

    def test_key_xor_byte(self):
        plaintext = conversions.ascii_to_bytes("a c ")
        key = conversions.ascii_to_bytes(" b")
        ciphertext = conversions.ascii_to_bytes("ABCB")
        self.assertEqual(ciphertext, bytes(ciphers.xor_seq_key(plaintext, key)))

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

class TestModernCiphersFunctions(unittest.TestCase):
    def test_aes_128_cbc(self):
        target = "I'm back and I'm ringin' the bell \nA rockin' on "

        ciphertext = conversions.base64_to_bytes(utility.readfile('test_data/test_aes_cbc_128.txt'))
        plaintext = ciphers.aes_128_cbc_decrypt(ciphertext, "YELLOW SUBMARINE", conversions.hex_to_bytes("00000000000000000000000000000000"))
        plaintext = conversions.bytes_to_ascii(plaintext)
        self.assertEqual(target, plaintext)