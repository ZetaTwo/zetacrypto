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
    def text_generate_key(self):
        for keylen in range(10):
            k = ciphers.generate_key(keylen)
            self.assertEqual(keylen, len(k))

    def test_pkcs7_pad(self):
        """Set 2 problem 1"""
        plaintext = conversions.ascii_to_bytes("YELLOW SUBMARINE")
        ciphertext = b"YELLOW SUBMARINE\x04\x04\x04\x04"
        c1 = ciphers.pkcs7_pad(plaintext, 20)
        self.assertEqual(ciphertext, c1)

        c2 = ciphers.pkcs7_pad(plaintext, 10)
        self.assertEqual(ciphertext, c2)

    def test_pkcs7_verify(self):
        ciphertext1 = b"YELLOW SUBMARINE\x04\x04\x04\x04"
        ciphertext2 = b"YELLOW SUBMARINE\x05\x05\x05\x05"
        self.assertTrue(ciphers.pkcs7_verify(ciphertext1))
        self.assertFalse(ciphers.pkcs7_verify(ciphertext2))

    def test_pkcs7_strip(self):
        plaintext = conversions.ascii_to_bytes("YELLOW SUBMARINE")
        ciphertext = b"YELLOW SUBMARINE\x04\x04\x04\x04"
        m = ciphers.pkcs7_strip(ciphertext)
        self.assertEqual(plaintext, m)

class TestModernCiphersFunctions(unittest.TestCase):
    def test_aes_128_cbc_decrypt(self):
        plaintext = "I'm back and I'm ringin' the bell \nA rockin' on "
        ciphertext = conversions.base64_to_bytes(utility.readfile('test_data/test_aes_cbc_128.txt'))

        m = ciphers.aes_128_cbc_decrypt(ciphertext, "YELLOW SUBMARINE", conversions.hex_to_bytes("00000000000000000000000000000000"))
        m = conversions.bytes_to_ascii(m)
        self.assertEqual(plaintext, m)

    def test_aes_128_cbc_encrypt(self):
        plaintext = "I'm back and I'm ringin' the bell \nA rockin' on "
        ciphertext = conversions.base64_to_bytes(utility.readfile('test_data/test_aes_cbc_128.txt'))

        c = ciphers.aes_128_cbc_encrypt(conversions.ascii_to_bytes(plaintext), "YELLOW SUBMARINE", conversions.hex_to_bytes("00000000000000000000000000000000"))
        self.assertEqual(ciphertext, c)

    def test_aes_128_ecb_decrypt(self):
        key = "YELLOW SUBMARINE"
        plaintext = utility.readfile('data/play_that_funky_music.txt')
        ciphertext = conversions.base64_to_bytes(utility.readfile('data/7.txt'))

        m = ciphers.aes_128_ecb_decrypt(ciphertext, key)
        self.assertTrue(ciphers.pkcs7_verify(m))
        m = ciphers.pkcs7_strip(m)
        m = conversions.bytes_to_ascii(m)
        self.assertEqual(plaintext, m)

    def test_aes_128_ecb_encrypt(self):
        key = "YELLOW SUBMARINE"
        plaintext = conversions.ascii_to_bytes(utility.readfile('data/play_that_funky_music.txt'))
        ciphertext = conversions.base64_to_bytes(utility.readfile('data/7.txt'))

        m = ciphers.pkcs7_pad(plaintext, 16)
        c = ciphers.aes_128_ecb_encrypt(m, key)
        self.assertEqual(ciphertext, c)

if __name__ == '__main__':
    unittest.main()
