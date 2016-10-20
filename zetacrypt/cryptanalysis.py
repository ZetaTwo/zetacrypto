__author__ = 'Calle Svensson <calle.svensson@zeta-two.com>'

import string, operator, scipy.stats
from scipy.stats.distributions import chi2
from collections import Counter

from . import conversions, utility, mathtools, INF, BYTE_MAX
from zetacrypt.ciphers import xor_seq_byte

# The relative frequency of alphabet letters in the English language
# FREQ_ENGLISH = {'e': 0.12575645, 't': 0.9085226, 'a': 0.8000395, 'o': 0.7591270, 'i': 0.6920007, 'n': 0.6903785,
#                's': 0.6340880, 'h': 0.6236609, 'r': 0.5959034, 'd': 0.4317924, 'l': 0.4057231, 'u': 0.2841783,
#                'c': 0.2575785, 'm': 0.2560994, 'f': 0.2350463, 'w': 0.2224893, 'g': 0.1982677, 'y': 0.1900888,
#                'p': 0.1795742, 'b': 0.1535701, 'v': 0.0981717, 'k': 0.0739906, 'x': 0.0179556, 'j': 0.0145188,
#                'q': 0.0117571, 'z': 0.0079130}
FREQ_ENGLISH = {'e': 0.12702, 't': 0.09056, 'a': 0.08167, 'o': 0.07507, 'i': 0.06966, 'n': 0.06749, 's': 0.06327,
                'h': 0.06094, 'r': 0.05987, 'd': 0.04253, 'l': 0.04025, 'c': 0.02782, 'u': 0.02758, 'm': 0.02406,
                'w': 0.02361, 'f': 0.02228, 'g': 0.02015, 'y': 0.01974, 'p': 0.01929, 'b': 0.01492, 'v': 0.00978,
                'k': 0.00772, 'j': 0.00153, 'x': 0.00150, 'q': 0.00095, 'z': 0.00074}
IC_ENGLISH = 1.73


def get_expected_freq(message_len, freq):
    return dict((k, v * message_len) for k, v in freq.items())


def count_printable(seq):
    """Returns the number of printable ASCII characters in seq"""
    return len(list(filter(lambda c: 32 <= c < 127 or c == ord('\n'), seq)))


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
    if total == 0:
        return freq
    else:
        return {k: v / total for k, v in freq.items()}


def index_coincidence(seq):
    """Returns the index of coincidence for a sequence"""
    freq = letter_frequency(seq)
    return len(string.ascii_lowercase) * sum(map(lambda x: x * (x - 1), freq.values())) / (len(seq) * (len(seq) - 1))


def chi_square_letter_freq(freq, expected):
    obs = list(map(operator.itemgetter(1), sorted(freq.items(), key=operator.itemgetter(0))))
    expected = list(map(operator.itemgetter(1), sorted(expected.items(), key=operator.itemgetter(0))))
    chival, _ = scipy.stats.chisquare(obs, expected)
    return chival


def find_single_byte_xor_key(seq):
    """Find the most probable single byte XOR key used to encrypt seq"""
    best_dist = INF
    best_key = 0
    best = "FAIL"
    for key in range(BYTE_MAX):
        mb = bytes(xor_seq_byte(seq, key))

        if not is_printable(mb):
            continue

        m = conversions.bytes_to_ascii(mb)

        freq = letter_frequency(m)
        dist = chi_square_letter_freq(freq, get_expected_freq(len(m), FREQ_ENGLISH))

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
        prev_block = next(blocks)
        for block in blocks:
            dist.append(float(mathtools.hamming_distance_bit(prev_block, block)) / keysize)
            prev_block = block
        dist = sum(dist) / len(dist)

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
    return bytes(key)


def count_repeated_blocks(ciphertext, block_size):
    blocks = Counter(utility.chunks(ciphertext, block_size))
    return blocks.most_common(1)[0][1]


def detect_ecb(ciphertext, block_size):
    return count_repeated_blocks(ciphertext, block_size) > 1


def encryption_detection_oracle_ecb_cbc(oracle, blocklen, answer=False):
    plaintext = conversions.ascii_to_bytes("A" * (16 * 3))
    if answer:  # If black box supports it, leak real answer
        c, ans = oracle(plaintext, True)
        return detect_ecb(c, blocklen), ans
    else:  # Otherwise, just return guess
        c = oracle(plaintext)
        return detect_ecb(c, blocklen)


def find_ecb_block_length(blackbox):
    """Finds out the block length of a ECB encryption function."""
    # Find start of new block
    secret_len = len(blackbox(b""))
    for block_start_cand in range(256):
        newlen = len(blackbox(b"A" * block_start_cand))
        if newlen > secret_len:
            baseline = newlen
            block_start = block_start_cand
            break

    # Find block len
    for block_len_cand in range(256):
        newlen = len(blackbox(b"A" * (block_len_cand + block_start)))
        if newlen > baseline:
            return block_len_cand


def decrypt_ecb_postfix(blackbox, block_size):
    """Decrypts the postfix part of an ECB like encryption function"""

    # Number of blocks to decrypt
    secret_len = len(blackbox(b""))
    secret_blocks = (secret_len + block_size - 1) // block_size

    # For each block
    message = bytes()
    for block in range(secret_blocks):
        # For each element in the block
        for element in range(block_size):
            # Calculate target block
            block_base = (block_size - element - 1) * b"A"
            block_cipher_base = blackbox(block_base)[:(block + 1) * block_size]

            # Try all bytes to get matching block
            for b in range(BYTE_MAX):
                guess_byte = bytes([b])
                block_guess = block_base + message + guess_byte
                block_cipher_guess = blackbox(block_guess)[:(block + 1) * block_size]

                # Append to message and move to next element
                if block_cipher_base == block_cipher_guess:
                    message += guess_byte
                    break
    return message
