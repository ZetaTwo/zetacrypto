__author__ = 'Calle Svensson <calle.svensson@zeta-two.com>'
import itertools

from Crypto.Cipher import AES
from . import utility


def xor_seq_byte(seq, key):
    """Returns seq XOR:ed with single byte key"""
    return map(lambda x: x ^ key, seq)


def xor_seq_key(seq, key):
    """Returns seq XOR:ed with key repeated to cover all of seq"""
    if type(seq) == str:
        seq = map(ord, seq)
    if type(key) == str:
        key = map(ord, key)
    return map(lambda x: x[0] ^ x[1], zip(itertools.cycle(key), seq))


def pkcs7(seq, targetlen):
    padlen = targetlen - len(seq)
    assert padlen >= 0
    return seq + bytes([padlen]*padlen)


def aes_128_cbc_decrypt(cipher, key, iv):
    aes = AES.new(key, AES.MODE_ECB)

    plaintext = []
    prev = iv
    for block in utility.chunks(cipher, 16):
        dec = aes.decrypt(block)
        plaintext += xor_seq_key(dec, prev)
        prev = block

    return plaintext

