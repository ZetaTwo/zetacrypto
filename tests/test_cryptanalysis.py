__author__ = 'Calle Svensson <calle.svensson@zeta-two.com>'
import unittest

import string
from zetacrypt import cryptanalysis, ciphers, conversions, utility


class TestTextFunctions(unittest.TestCase):
    def test_count_printable(self):
        data = conversions.ascii_to_bytes(" amzANZ019%/")
        self.assertEqual(12, cryptanalysis.count_printable(data))

    def test_is_printable1(self):
        data = conversions.ascii_to_bytes(" amzANZ019%/")
        self.assertTrue(cryptanalysis.is_printable(data))

    def test_is_printable2(self):
        data = conversions.ascii_to_bytes(" amzANZ019%/\x10")
        self.assertFalse(cryptanalysis.is_printable(data))

    def test_letter_freq(self):
        target = {k: 0 for k in string.ascii_lowercase}
        target['x'] = 2
        target['y'] = 2
        target['z'] = 2
        target['a'] = 1
        target['b'] = 1
        data = "xyzxyzab"
        freq = cryptanalysis.letter_frequency(data)
        self.assertEqual(target, freq)

    def test_letter_freq_rel(self):
        target = {k: 0 for k in string.ascii_lowercase}
        target['a'] = 0.5
        target['m'] = 0.5
        data = "amamam"
        freq = cryptanalysis.letter_frequency_rel(data)
        self.assertEqual(target, freq)

    def test_letter_freq_rel_empty(self):
        data = ""
        freq = cryptanalysis.letter_frequency_rel(data)

    def test_index_coincidence(self):
        text = "QPWKALVRXCQZIKGRBPFAEOMFLJMSDZVDHXCXJYEBIMTRQWNMEAIZRVKCVKVLXNEICFZPZCZZHKMLVZVZIZRRQWDKECHOSNYXXLSPMYKVQXJTDCIOMEEXDQVSRXLRLKZHOV"
        ic5 = 1.82
        ic9 = 1.17

        icdelta5 = 0
        for tr in utility.transpose(text, 5):
            icdelta5 += cryptanalysis.index_coincidence(tr)
        self.assertEqual(ic5, round(icdelta5/5, 2))

        icdelta9 = 0
        for tr in utility.transpose(text, 9):
            icdelta9 += cryptanalysis.index_coincidence(tr)
        self.assertEqual(ic9, round(icdelta9/9, 2))


class TextXorFunctions(unittest.TestCase):
    def test_find_single_byte_xor_key(self):
        """Set 1 problem 3"""
        ciphertext = conversions.hex_to_bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
        plaintext = "Cooking MC's like a pound of bacon"
        key = 88

        m, k, _ = cryptanalysis.find_single_byte_xor_key(ciphertext)
        print(k, m)
        self.assertEqual(key, k)
        self.assertEqual(plaintext, m)

class TestVigenereFunctions(unittest.TestCase):
    def test_find_vigenere_key_len(self):
        ciphertext = utility.readfile('test_data/vigenere1.txt')
        ciphertext = conversions.base64_to_bytes(ciphertext)

        keysize = cryptanalysis.find_vigenere_key_len(ciphertext, 2, 40)
        self.assertEqual(29, keysize)

    def test_find_vigenere_key(self):
        target = conversions.ascii_to_bytes("Terminator X: Bring the noise")
        ciphertext = utility.readfile('test_data/vigenere1.txt')
        ciphertext = conversions.base64_to_bytes(ciphertext)

        keysize = 29
        key = cryptanalysis.find_vigenere_key(ciphertext, keysize)
        self.assertEqual(target, key)

class TextModernCryptoFunctions(unittest.TestCase):
    def test_detect_ecb(self):
        blocklen = 16
        target_index = 132
        found_index = -1
        with open('data/8.txt') as cipherfile:
            i = 0
            for hexline in cipherfile:
                hexline = hexline.strip()
                byteline = conversions.bytes_to_ascii(conversions.hex_to_bytes(hexline))
                if cryptanalysis.detect_ecb(byteline, blocklen):
                    found_index = i
                    break
                i += 1

        self.assertEqual(target_index, found_index)

    def test_ecb_cbc_oracle(self):
        blocklen = 16
        for i in range(100):
            guess, real = cryptanalysis.encryption_detection_oracle_ecb_cbc(ciphers.black_box1, blocklen, True)
            self.assertEqual(real, guess)

    def test_ecb_find_block_length(self):
        plaintext = utility.readfile('data/12.txt')
        plaintext = conversions.base64_to_bytes(plaintext)
        bb = ciphers.BlackBox2(plaintext)

        self.assertEqual(16, cryptanalysis.find_ecb_block_length(bb))

    def test_decrypt_ecb_postfix(self):
        blocklen = 16
        plaintext = utility.readfile('data/12.txt')
        plaintext = conversions.base64_to_bytes(plaintext)
        bb = ciphers.BlackBox2(plaintext)

        message = cryptanalysis.decrypt_ecb_postfix(bb, blocklen)
        message = ciphers.pkcs7_strip(message)

        self.assertEqual(plaintext, message)


if __name__ == '__main__':
    unittest.main()
