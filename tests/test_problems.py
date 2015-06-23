__author__ = 'Calle'
import unittest

from zetacrypt import conversions, utility, ciphers, cryptanalysis, INF
from Crypto.Cipher import AES
from collections import Counter


class TestSet1Problems(unittest.TestCase):
    """Set 1: Basics"""

    def test_problem1(self):
        """Convert hex to base64"""
        targettext = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        plaintext = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

        res = str(conversions.bytes_to_base64(conversions.hex_to_bytes(plaintext)))
        self.assertEqual(targettext, res)

    def test_problem2(self):
        """Fixed XOR"""
        ciphertext = "746865206b696420646f6e277420706c6179"
        key = conversions.hex_to_bytes("686974207468652062756c6c277320657965")
        plaintext = conversions.hex_to_bytes("1c0111001f010100061a024b53535009181c")

        res = ciphers.xor_seq_key(plaintext, key)
        res = conversions.bytes_to_hex(res)
        self.assertEqual(ciphertext, res)

    def test_problem3(self):
        """Single-byte XOR cipher"""
        ciphertext = conversions.hex_to_bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
        plaintext = "Cooking MC's like a pound of bacon"
        key = 88

        m, k, _ = cryptanalysis.find_single_byte_xor_key(ciphertext)
        self.assertEqual(key, k)
        self.assertEqual(plaintext, m)

    def test_problem4(self):
        """Detect single-character XOR"""
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
        """Implement repeating-key XOR"""
        plaintext = conversions.ascii_to_bytes(
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
        key = conversions.ascii_to_bytes("ICE")
        ciphertext = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272" \
                     "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

        res = ciphers.xor_seq_key(plaintext, key)
        res = conversions.bytes_to_hex(res)
        self.assertEqual(ciphertext, res)

    def test_problem6(self):
        """Break repeating-key XOR"""
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
        """AES in ECB mode"""
        blocklen = 16
        key = "YELLOW SUBMARINE"
        plaintext = utility.readfile('data/play_that_funky_music.txt')
        ciphertext = conversions.base64_to_bytes(utility.readfile('data/7.txt'))

        m = ciphers.aes_128_ecb_decrypt(ciphertext, key)
        self.assertTrue(ciphers.pkcs7_verify(m, blocklen))
        m = ciphers.pkcs7_strip(m)
        m = conversions.bytes_to_ascii(m)
        self.assertEqual(plaintext, m)

    def test_problem8(self):
        """Detect AES in ECB mode"""
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


class TestSet2Problems(unittest.TestCase):
    """Set 2: Block crypto"""

    def test_problem9(self):
        """Implement PKCS#7 padding"""
        plaintext = conversions.ascii_to_bytes("YELLOW SUBMARINE")
        ciphertext = "YELLOW SUBMARINE\x04\x04\x04\x04"
        c = ciphers.pkcs7_pad(plaintext, 20)
        c = conversions.bytes_to_ascii(c)

        self.assertEqual(ciphertext, c)

    def test_problem10(self):
        """Implement CBC mode"""
        blocklen = 16
        plaintext = utility.readfile('data/play_that_funky_music.txt')
        ciphertext = conversions.base64_to_bytes(utility.readfile('data/10.txt'))

        # Decrypt
        m = ciphers.aes_128_cbc_decrypt(ciphertext, "YELLOW SUBMARINE", conversions.hex_to_bytes("00000000000000000000000000000000"))

        # Verify padding and content
        self.assertTrue(ciphers.pkcs7_verify(m, blocklen))
        m = ciphers.pkcs7_strip(m)
        m = conversions.bytes_to_ascii(m)
        self.assertEqual(plaintext, m)

    def test_problem11(self):
        """An ECB/CBC detection oracle"""
        blocklen = 16
        for i in range(100):
            guess, real = cryptanalysis.encryption_detection_oracle_ecb_cbc(ciphers.black_box1, blocklen, True)
            self.assertEqual(real, guess)

    def test_problem12(self):
        """Byte-at-a-time ECB decryption (Simple)"""
        plaintext = utility.readfile('data/12.txt')
        plaintext = conversions.base64_to_bytes(plaintext)

        # Find block length
        blackbox = ciphers.BlackBox2(plaintext)
        block_len = cryptanalysis.find_ecb_block_length(blackbox)
        self.assertEqual(16, block_len)

        # Detect ECB
        self.assertTrue(cryptanalysis.detect_ecb(blackbox(b"A" * 2 * block_len), block_len))

        # Decode message
        message = cryptanalysis.decrypt_ecb_postfix(blackbox, block_len)
        message = ciphers.pkcs7_strip(message)
        self.assertEqual(plaintext, message)
        print(conversions.bytes_to_ascii(message))

    def test_problem13(self):
        """ECB cut-and-paste"""
        enc = ciphers.ProfileEncoder1()

        profile1 = enc.profile_for('aaaaaaaaaa' + str(ciphers.pkcs7_pad(conversions.ascii_to_bytes('admin'), enc.BLOCKLEN), 'ascii') + '@b.com')
        admin_block = profile1[1*enc.BLOCKLEN:2*enc.BLOCKLEN]

        profile2 = enc.profile_for('l33t_h4cker_sk1ll@zeta-two.com')
        profile_blocks = profile2[:3*enc.BLOCKLEN]

        profile3 = profile_blocks + admin_block
        admin = enc.parse_ciphertext(profile3)

        print(admin)
        self.assertEqual('admin', admin['role'])

    def test_problem15(self):
        """PKCS#7 padding validation"""
        blocklen = 10
        ciphertext1 = b"YELLOW SUBMARINE\x04\x04\x04\x04"
        self.assertTrue(ciphers.pkcs7_verify(ciphertext1, blocklen))

        ciphertext2 = b"YELLOW SUBMARINE\x05\x05\x05\x05"
        self.assertFalse(ciphers.pkcs7_verify(ciphertext2, blocklen))

        ciphertext3 = b"YELLOW SUBMARIN\x04\x04\x04\x04"
        self.assertFalse(ciphers.pkcs7_verify(ciphertext3, blocklen))

        plaintext = conversions.ascii_to_bytes("YELLOW SUBMARINE")
        ciphertext = b"YELLOW SUBMARINE\x04\x04\x04\x04"
        m = ciphers.pkcs7_strip(ciphertext)
        self.assertEqual(plaintext, m)

if __name__ == '__main__':
    unittest.main()
