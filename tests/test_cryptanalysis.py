__author__ = 'Calle Svensson <calle.svensson@zeta-two.com>'
import unittest

import base64, string
from zetacrypt import cryptanalysis, conversions, utility


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
        ciphertext = utility.readfile('data/vigenere1.txt')
        ciphertext = base64.b64decode(ciphertext)

        keysize = cryptanalysis.find_vigenere_key_len(ciphertext, 2, 40)
        self.assertEqual(29, keysize)

    def test_find_vigenere_key(self):
        target = conversions.ascii_to_bytes("Terminator X: Bring the noise")
        ciphertext = utility.readfile('data/vigenere1.txt')
        ciphertext = base64.b64decode(ciphertext)

        keysize = 29
        key = cryptanalysis.find_vigenere_key(ciphertext, keysize)
        self.assertEqual(target, key)

if __name__ == '__main__':
    unittest.main()
