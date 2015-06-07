from zetacrypt import *

import base64

# Problem 1
def problem1():
    plaintext = conversions.ascii_to_bytes("YELLOW SUBMARINE")
    ciphertext = "YELLOW SUBMARINE\x04\x04\x04\x04"
    c = ciphers.pkcs7(plaintext, 20)
    c = conversions.bytes_to_ascii(c)
    print(ciphertext == c)

# Problem 2
def problem2():
    ciphertext = base64.b64decode(utility.readfile('10.txt'))
    plaintext = ciphers.aes_128_cbc_decrypt(ciphertext, "YELLOW SUBMARINE", conversions.hex_to_bytes("00000000000000000000000000000000"))
    print(conversions.bytes_to_ascii(plaintext))

problem1()
problem2()
