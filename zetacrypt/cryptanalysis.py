__author__ = 'Calle Svensson <calle.svensson@zeta-two.com>'

import string
from collections import Counter

from zetacrypt import INF, BYTE_MAX
from mathtools import rms_error, hamming_distance_bit
from ciphers import xor_seq_byte


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
    return len(filter(lambda c: 32 <= c <= 126, seq))


def is_printable(seq):
    """Returns true is seq consists solely of printable ASCII characters"""
    return len(seq) == count_printable(seq)


def letter_frequency(seq):
    """Returns a dictionary with the frequencies of letters in the sequence"""
    freq = filter(lambda x: x in string.letters, seq.lower())
    freq = dict(Counter(freq).most_common())
    freq.update(dict((x, 0) for x in filter(lambda x: x not in freq, string.lowercase)))
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
        seq = map(ord, seq)
    best_dist = INF
    best_key = 0
    best = "FAIL"
    for key in range(BYTE_MAX):
        m = xor_seq_byte(seq, key)
        m = ''.join(map(chr, m))

        if count_printable(m) < len(m) * printable_threshold:
            continue

        freq = letter_frequency_rel(m)
        dist = rms_error(freq, FREQ_ENGLISH)
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
        dist = 0
        num_blocks = len(cipher) / keysize
        for i in range(num_blocks):
            block1 = cipher[i * keysize:(i + 1) * keysize]
            block2 = cipher[(i + 1) * keysize:(i + 2) * keysize]
            dist += float(hamming_distance_bit(block1, block2)) / keysize
        dist /= num_blocks

        # If better, save
        if dist < best_dist:
            best_dist = dist
            best_keysize = keysize
    return best_keysize


def find_vigenere_key(cipher, keylen):
    """Breaks a vigenere cipher with known keylen"""
    key = []
    for i in range(keylen):
        _, k, _ = find_single_byte_xor_key(cipher[i::keylen])
        key.append(k)
    return key