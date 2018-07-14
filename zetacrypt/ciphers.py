from __future__ import unicode_literals
__author__ = 'Calle Svensson <calle.svensson@zeta-two.com>'
from future.standard_library import install_aliases
from future.utils import tobytes
from six import byte2int, int2byte
install_aliases()
from builtins import bytes, str, filter, map

import itertools
import struct

from Crypto.Cipher import AES
from random import randint
from urllib.parse import parse_qs
from collections import OrderedDict
from . import utility
from .conversions import *
import re


def xor_seq_byte(seq, key):
    """Returns seq XOR:ed with single byte key"""
    return map(lambda x: int2byte(x ^ byte2int(key)), seq)


def xor_seq_key(seq, key):
    """Returns seq XOR:ed with key repeated to cover all of seq"""
    key = map(byte2int, key)
    return map(lambda x: int2byte(byte2int(x[0]) ^ x[1]), zip(seq, itertools.cycle(key)))


def pkcs7_pad(seq, blocklen):
    """Pad seq to a length which is an integer multiple of blocklen by the PKCS#7 standard"""
    seq_len = 0
    for c in seq:
        seq_len += 1
        yield c

    padlen = blocklen - (seq_len % blocklen)
    assert padlen >= 0
    
    for i in range(padlen):
        yield padlen


def pkcs7_verify(seq, blocklen):
    """Verifies that seq is a properly padded PKCS#7 sequence"""
    assert(type(seq) == bytes)
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
    return bytes(aes.decrypt(ciphertext))


def aes_128_cbc_encrypt(plaintext, key, iv):
    aes = AES.new(key, AES.MODE_ECB)
    assert len(iv) == len(key) == 16
    assert type(iv) == bytes
    assert type(plaintext) == bytes

    cipertext = []
    prev = iv
    for block in utility.chunks(plaintext, 16):
        m = iterator_to_bytes(xor_seq_key(block, prev))
        c = bytes(aes.encrypt(m))
        cipertext += c
        prev = c

    return bytes(cipertext)


def aes_128_cbc_decrypt(cipher, key, iv):
    assert len(iv) == len(key) == 16
    assert type(cipher) == bytes
    assert type(iv) == bytes
    
    aes = AES.new(key, AES.MODE_ECB)

    plaintext = bytes()
    prev = iv
    for block in utility.chunks(cipher, 16):
        dec = bytes(aes.decrypt(block))
        plaintext += iterator_to_bytes(xor_seq_key(dec, prev))
        prev = block

    return plaintext


def generate_key(keylen):
    return bytes([randint(0, 255) for _ in range(keylen)])


def black_box1(plaintext, answer=False):
    key = generate_key(16)
    prepend = generate_key(randint(5, 10))
    append = generate_key(randint(5, 10))

    m = pkcs7_pad(itertools.chain(prepend, plaintext, append), 16)

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
        plaintext = ascii_to_bytes(plaintext)
        padded = pkcs7_pad(itertools.chain(plaintext, self.ciphertext), self.BLOCKLEN)
        m = iterator_to_bytes(padded)
        return aes_128_ecb_encrypt(m, self.key)


class ProfileEncoder1:
    BLOCKLEN = 16

    def __init__(self):
        self.key = generate_key(self.BLOCKLEN)
        self.next_user_id = 0

    def create_profile(self, email):
        email = re.sub('[=&]', '', email)
        self.next_user_id += 1
        return 'email=' + email + '&uid=' + str(self.next_user_id) + '&role=user'

    def profile_for(self, email):
        m = iterator_to_bytes(pkcs7_pad(tobytes(self.create_profile(email)), self.BLOCKLEN))
        return aes_128_ecb_encrypt(m, self.key)

    @staticmethod
    def parse_profile(profile_string):
        return {k: v[0] for (k, v) in parse_qs(profile_string).items()}

    def parse_ciphertext(self, ciphertext):
        profile_string = aes_128_ecb_decrypt(ciphertext, self.key)
        if not pkcs7_verify(profile_string, self.BLOCKLEN):
            return None
        profile_string = bytes_to_ascii(pkcs7_strip(profile_string))
        return self.parse_profile(profile_string)
