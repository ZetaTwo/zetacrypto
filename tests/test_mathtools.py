__author__ = 'Calle'
import unittest

from zetacrypt import mathtools


class TestMathFunctions(unittest.TestCase):
    def test_swap_count(self):
        self.assertEqual(1, mathtools.levenshtein_swap("abcd", "bacd"))
        self.assertEqual(0, mathtools.levenshtein_swap("abcd", "abcd"))
        self.assertEqual(2, mathtools.levenshtein_swap("abcd", "badc"))

    def test_hamming_weight(self):
        self.assertEqual(3, mathtools.hamming_weight(7))
        self.assertEqual(1, mathtools.hamming_weight(4))
        self.assertEqual(0, mathtools.hamming_weight(0))

    def test_hamming_distance_char(self):
        self.assertEqual(1, mathtools.hamming_distance_char("abc", "abd"))

    def test_hamming_distance_bit(self):
        self.assertEqual(37, mathtools.hamming_distance_bit("this is a test", "wokka wokka!!!"))

    def test_mean(self):
        self.assertEqual(0, mathtools.mean([-1, 0, 1]))
        self.assertEqual(2, mathtools.mean([1, 2, 3]))

    def test_rms_error(self):
        self.assertEqual(2, mathtools.rms_error([0, 1, 2], [2, 3, 0]))


if __name__ == '__main__':
    unittest.main()
