from zetacrypt import *


# Problem 1
def problem1():
    plaintext = conversions.ascii_to_byte("YELLOW SUBMARINE")
    ciphertext = "YELLOW SUBMARINE\x04\x04\x04\x04"
    c = ciphers.pkcs7(plaintext, 20)
    c = conversions.byte_to_ascii(c)
    print(ciphertext == c)

problem1()