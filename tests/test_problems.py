__author__ = 'Calle'
import unittest

from zetacrypt import conversions, utility, ciphers, cryptanalysis, INF
from Crypto.Cipher import AES
from collections import Counter


class TestSet1Problems(unittest.TestCase):
    def test_problem1(self):
        targettext = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        plaintext = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

        res = str(conversions.bytes_to_base64(conversions.hex_to_bytes(plaintext)))
        self.assertEqual(targettext, res)

    def test_problem2(self):
        ciphertext = "746865206b696420646f6e277420706c6179"
        key = conversions.hex_to_bytes("686974207468652062756c6c277320657965")
        plaintext = conversions.hex_to_bytes("1c0111001f010100061a024b53535009181c")

        res = ciphers.xor_seq_key(plaintext, key)
        res = conversions.bytes_to_hex(res)
        self.assertEqual(ciphertext, res)

    def test_problem3(self):
        ciphertext = conversions.hex_to_bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
        plaintext = "Cooking MC's like a pound of bacon"
        key = 88

        m, k, _ = cryptanalysis.find_single_byte_xor_key(ciphertext)
        self.assertEqual(key, k)
        self.assertEqual(plaintext, m)

    def test_problem4(self):
        plaintext = "Now that the party is jumping\n"

        with open('data/4.txt', 'r') as cipherfile:
            best = 'FAIL'
            best_dist = INF
            for hexline in cipherfile:
                byteline = conversions.hex_to_bytes(hexline.strip())
                m, key, dist = cryptanalysis.find_single_byte_xor_key(byteline)
                if dist < best_dist:
                    best = m
                    best_dist = dist

        self.assertEqual(plaintext, best)

    def test_problem5(self):
        plaintext = conversions.ascii_to_bytes(
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
        key = conversions.ascii_to_bytes("ICE")
        ciphertext = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272" \
                     "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

        res = ciphers.xor_seq_key(plaintext, key)
        res = conversions.bytes_to_hex(res)
        self.assertEqual(ciphertext, res)

    def test_problem6(self):
        target_keylen = 29
        target_key = conversions.ascii_to_bytes("Terminator X: Bring the noise")
        plaintext = utility.readfile('data/play_that_funky_music.txt')

        # Read input
        ciphertext = utility.readfile('data/6.txt')
        ciphertext = conversions.base64_to_bytes(ciphertext)

        # Decrypt
        keysize = cryptanalysis.find_vigenere_key_len(ciphertext, 2, 40)
        self.assertEqual(target_keylen, keysize)

        key = cryptanalysis.find_vigenere_key(ciphertext, keysize)
        self.assertEqual(target_key, key)

        m = ciphers.xor_seq_key(ciphertext, key)
        m = conversions.bytes_to_ascii(m)
        self.assertEqual(plaintext, m)

    def test_problem7(self):
        key = "YELLOW SUBMARINE"
        plaintext = utility.readfile('data/play_that_funky_music.txt') + '\x04\x04\x04\x04'

        ciphertext = conversions.base64_to_bytes(utility.readfile('data/7.txt'))
        aes = AES.new(key, AES.MODE_ECB)
        m = conversions.bytes_to_ascii(aes.decrypt(ciphertext))
        self.assertEqual(plaintext, m)

    def test_problem8(self):
        block_size = 16
        best = 'FAIL'
        best_count = 0
        best_index = 0
        with open('data/8.txt') as cipherfile:
            i = 0
            for hexline in cipherfile:
                hexline = hexline.strip()
                byteline = conversions.bytes_to_ascii(conversions.hex_to_bytes(hexline))
                blocks = Counter(utility.chunks(byteline, block_size))
                count = blocks.most_common(1)[0][1]
                if count > best_count:
                    best_count = count
                    best = hexline
                    best_index = i
                i += 1

        print(best_index, best_count, best)


class TestSet2Problems(unittest.TestCase):
    def test_problem9(self):
        plaintext = conversions.ascii_to_bytes("YELLOW SUBMARINE")
        ciphertext = "YELLOW SUBMARINE\x04\x04\x04\x04"
        c = ciphers.pkcs7(plaintext, 20)
        c = conversions.bytes_to_ascii(c)

        self.assertEqual(ciphertext, c)

    def test_problem10(self):
        plaintext = utility.readfile('data/play_that_funky_music.txt') + '\x04\x04\x04\x04'
        ciphertext = conversions.base64_to_bytes(utility.readfile('data/10.txt'))

        m = ciphers.aes_128_cbc_decrypt(ciphertext, "YELLOW SUBMARINE", conversions.hex_to_bytes("00000000000000000000000000000000"))
        m = conversions.bytes_to_ascii(m)

        self.assertEqual(plaintext, m)
