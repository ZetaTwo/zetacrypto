__author__ = 'Calle Svensson <calle.svensson@zeta-two.com>'

import string
from collections import Counter

from . import conversions, utility, mathtools, INF, BYTE_MAX
from zetacrypt.ciphers import xor_seq_byte


# The relative frequency of alphabet letters in the English language
FREQ_ENGLISH = {'e': 0.12575645, 't': 0.9085226, 'a': 0.8000395, 'o': 0.7591270, 'i': 0.6920007, 'n': 0.6903785,
                's': 0.6340880, 'h': 0.6236609, 'r': 0.5959034, 'd': 0.4317924, 'l': 0.4057231, 'u': 0.2841783,
                'c': 0.2575785, 'm': 0.2560994, 'f': 0.2350463, 'w': 0.2224893, 'g': 0.1982677, 'y': 0.1900888,
                'p': 0.1795742, 'b': 0.1535701, 'v': 0.0981717, 'k': 0.0739906, 'x': 0.0179556, 'j': 0.0145188,
                'q': 0.0117571, 'z': 0.0079130}


def count_printable(seq):
    """Returns the number of printable ASCII characters in seq"""
    if type(seq) == str:
        seq = map(ord, seq)
    return len(list(filter(lambda c: 32 <= c <= 126, seq)))


def is_printable(seq):
    """Returns true is seq consists solely of printable ASCII characters"""
    return len(seq) == count_printable(seq)


def letter_frequency(seq):
    """Returns a dictionary with the frequencies of letters in the sequence"""
    freq = filter(lambda x: x in string.ascii_letters, seq.lower())
    freq = dict(Counter(freq).most_common())
    freq.update(dict((x, 0) for x in filter(lambda x: x not in freq, string.ascii_lowercase)))
    return freq


def letter_frequency_rel(seq):
    """Returns a dictionary with the relative frequency of letters in the sequence"""
    freq = letter_frequency(seq)
    total = len(seq)
    return {k: float(v) / total for k, v in freq.items()}


def index_coincidence(seq):
    """Returns the index of coincidence for a sequence"""
    raise NotImplementedError()


def find_single_byte_xor_key(seq, printable_threshold=0.85):
    """Find the most probable single byte XOR key used to encrypt seq"""
    if type(seq) == str:
        seq = conversions.ascii_to_byte(seq)
    best_dist = INF
    best_key = 0
    best = "FAIL"
    for key in range(BYTE_MAX):
        m = xor_seq_byte(seq, key)
        m = conversions.bytes_to_ascii(m)

        # If enough are printable, check letter frequency
        if count_printable(m) < len(m) * printable_threshold:
            continue
        freq = letter_frequency_rel(m)
        dist = mathtools.rms_error(freq, FREQ_ENGLISH)

        # If better, save
        if dist < best_dist:
            best = m
            best_key = key
            best_dist = dist
    return best, best_key, best_dist


def find_vigenere_key_len(cipher, mink, maxk):
    """Returns the most probable keylength in a vigenere based cipher"""
    best_dist = INF
    best_keysize = 0
    for keysize in range(mink, maxk):
        # Average hamming weight over BLOCKS
        dist = []
        blocks = utility.chunks(cipher, keysize)

        # Moving pairwise distance
        prev_block = blocks.next()
        for block in blocks:
            dist.append(float(mathtools.hamming_distance_bit(prev_block, block)) / keysize)
            prev_block = block
        dist = sum(dist)/len(dist)

        # If better, save
        if dist < best_dist:
            best_dist = dist
            best_keysize = keysize
    return best_keysize


def find_vigenere_key(cipher, keylen):
    """Breaks a vigenere cipher with known keylen"""
    key = []
    for block in utility.transpose(cipher, keylen):
        _, k, _ = find_single_byte_xor_key(block)
        key.append(k)
    return key
