__author__ = 'Calle'
import unittest

from zetacrypt import utility


class TestStreamFunctions(unittest.TestCase):
    def test_blocks(self):
        data = "abcddcbaxy"
        ch = utility.chunks(data, 4)
        self.assertEqual("abcd", ch.next())
        self.assertEqual("dcba", ch.next())
        self.assertEqual("xy", ch.next())

    def test_transpose(self):
        data = "abcdabcdabcdab"
        ch = utility.transpose(data, 4)
        self.assertEqual("aaaa", ch.next())
        self.assertEqual("bbbb", ch.next())
        self.assertEqual("ccc", ch.next())
        self.assertEqual("ddd", ch.next())

if __name__ == '__main__':
    unittest.main()
