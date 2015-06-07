import base64
from collections import Counter

from Crypto.Cipher import AES

from zetacrypt import *


# Problem 1
def problem1():
    targettext = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    plaintext = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

    res = str(base64.b64encode(conversions.hex_to_bytes(plaintext)), 'ascii')
    print(res == targettext, res)


# Problem 2
def problem2():
    ciphertext = "746865206b696420646f6e277420706c6179"
    key = conversions.hex_to_bytes("686974207468652062756c6c277320657965")
    plaintext = conversions.hex_to_bytes("1c0111001f010100061a024b53535009181c")

    res = ciphers.xor_seq_key(plaintext, key)
    res = conversions.bytes_to_hex(res)
    print(ciphertext == res, res)


# Problem 3
def problem3():
    ciphertext = conversions.hex_to_bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    print(cryptanalysis.find_single_byte_xor_key(ciphertext))


# Problem 4
def problem4():
    with open('4.txt', 'r') as cipherfile:
        best = 'FAIL'
        best_dist = INF
        for hexline in cipherfile:
            byteline = conversions.hex_to_bytes(hexline.strip())
            m, key, dist = cryptanalysis.find_single_byte_xor_key(byteline)
            if dist < best_dist:
                best = m
                best_dist = dist
        print(best)

# Problem 5
def problem5():
    plaintext = conversions.ascii_to_bytes("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
    key = conversions.ascii_to_bytes("ICE")
    ciphertext = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272" \
                 "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

    res = ciphers.xor_seq_key(plaintext, key)
    res = conversions.bytes_to_hex(res)
    print(res == ciphertext, res)


# Problem 6
def problem6():
    # Read input
    ciphertext = utility.readfile('6.txt')
    ciphertext = base64.b64decode(ciphertext)

    # Decrypt
    keysize = cryptanalysis.find_vigenere_key_len(ciphertext, 2, 40)
    print('Keysize', keysize)
    key = cryptanalysis.find_vigenere_key(ciphertext, keysize)
    print('Key', ''.join(map(chr, key)))
    m = ciphers.xor_seq_key(ciphertext, key)
    m = conversions.bytes_to_ascii(m)
    print(m)


# Problem 7
def problem7():
    key = "YELLOW SUBMARINE"
    ciphertext = base64.b64decode(utility.readfile('7.txt'))
    aes = AES.new(key, AES.MODE_ECB)
    m = conversions.bytes_to_ascii(aes.decrypt(ciphertext))
    print(m)


def problem8():
    block_size = 16
    best = 'FAIL'
    best_count = 0
    best_index = 0
    with open('8.txt') as cipherfile:
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


problem1()
problem2()
problem3()
problem4()
problem5()
problem6()
problem7()
problem8()
