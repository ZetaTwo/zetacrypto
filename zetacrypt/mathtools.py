__author__ = 'Calle Svensson <calle.svensson@zeta-two.com>'

import math, scipy


def levenshtein_swap(seq1, seq2):
    """Returns the number of pairwise swaps are needed to turn seq1 into seq2"""
    res = 0
    for i1 in range(len(seq1)):
        i2 = seq2.index(seq1[i1])
        res += abs(i1 - i2)
    return res / 2

def mean(seq):
    l = list(seq)
    return sum(l)/len(l)

def hamming_distance_char(seq1, seq2):
    """Returns the character hamming distance of two sequences of equal length"""
    return sum(map(lambda x: x[0] != x[1], zip(seq1, seq2)))


def hamming_weight(number):
    """Returns the number of bits set in number"""
    return bin(number).count("1")


def hamming_distance_bit(seq1, seq2):
    """Returns the bit hamming distance of two sequences of equal length"""
    if type(seq1) == str:
        seq1 = map(ord, seq1)
    if type(seq2) == str:
        seq2 = map(ord, seq2)
    return sum(map(lambda x: hamming_weight(x[0] ^ x[1]), zip(seq1, seq2)))


def rms_error(seq1, seq2):
    """Returns the RMS error between two lists of values"""
    assert len(seq1) == len(seq2)
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(seq1, seq2)) / len(seq1))


def rms_error_dict(dict1, dict2):
    """Returns the RMS error between two dictionaries with the same keys"""
    assert sorted(dict1.keys()) == sorted(dict2.keys())
    keys = dict1.keys()
    val1 = [dict1[k] for k in keys]
    val2 = [dict2[k] for k in keys]
    return rms_error(val1, val2)
