__author__ = 'Calle Svensson <calle.svensson@zeta-two.com>'
import itertools

from Crypto.Cipher import AES
from random import randint
from . import utility

def xor_seq_byte(seq, key):
    """Returns seq XOR:ed with single byte key"""
    return map(lambda x: x ^ key, seq)


def xor_seq_key(seq, key):
    """Returns seq XOR:ed with key repeated to cover all of seq"""
    return map(lambda x: x[0] ^ x[1], zip(itertools.cycle(key), seq))

def pkcs7_pad(seq, blocklen):
    """Pad seq to a length which is an integer multiple of blocklen by the PKCS#7 standard"""
    padlen = blocklen - (len(seq) % blocklen)
    assert padlen >= 0
    return seq + bytes([padlen]*padlen)

def pkcs7_verify(seq, blocklen):
    """Verifies that seq is a properly padded PKCS#7 sequence"""
    padlen = seq[-1]
    return (len(seq) % blocklen == 0) \
           and len(seq) >= padlen \
           and all(map(lambda x: x == padlen, seq[-padlen:]))

def pkcs7_strip(seq):
    """Strips away the PKCS#7 padding from seq"""
    padlen = seq[-1]
    return seq[:-padlen]

def aes_128_ecb_encrypt(plaintext, key):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(plaintext)

def aes_128_ecb_decrypt(ciphertext, key):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(ciphertext)

def aes_128_cbc_encrypt(plaintext, key, iv):
    aes = AES.new(key, AES.MODE_ECB)
    assert len(iv) == len(key) == 16

    cipertext = []
    prev = iv
    for block in utility.chunks(plaintext, 16):
        m = bytes(xor_seq_key(block, prev))
        c = aes.encrypt(m)
        cipertext += c
        prev = c

    return bytes(cipertext)

def aes_128_cbc_decrypt(cipher, key, iv):
    assert len(iv) == len(key) == 16
    aes = AES.new(key, AES.MODE_ECB)

    plaintext = []
    prev = iv
    for block in utility.chunks(cipher, 16):
        dec = aes.decrypt(block)
        plaintext += xor_seq_key(dec, prev)
        prev = block

    return plaintext

def generate_key(keylen):
    return bytes([randint(0, 255) for _ in range(keylen)])


def black_box1(plaintext, answer=False):
    key = generate_key(16)
    prepend = generate_key(randint(5, 10))
    append = generate_key(randint(5, 10))

    m = pkcs7_pad(prepend + plaintext + append, 16)

    mode = randint(0, 1)
    if mode == 0:  # CBC
        iv = generate_key(16)
        c = aes_128_cbc_encrypt(m, key, iv)
    else:  # ECB
        c = aes_128_ecb_encrypt(m, key)

    if answer:
        return c, mode
    else:
        return c

class BlackBox2:
    BLOCKLEN = 16

    def __init__(self, ciphertext):
        self.ciphertext = ciphertext
        self.key = generate_key(self.BLOCKLEN)

    def __call__(self, plaintext):
        m = pkcs7_pad(plaintext + self.ciphertext, self.BLOCKLEN)
        return aes_128_ecb_encrypt(m, self.key)

