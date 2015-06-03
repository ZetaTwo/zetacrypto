__author__ = 'Calle Svensson <calle.svensson@zeta-two.com>'
import itertools


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
    return seq + [padlen] * padlen
