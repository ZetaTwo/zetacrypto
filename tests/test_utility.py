__author__ = 'Calle'
import unittest

from zetacrypt import utility


class TestStreamFunctions(unittest.TestCase):
    def test_readfile(self):
        testdata = utility.readfile('test_data/testdata1.txt')
        self.assertEqual("Hello World!", testdata)

    def test_blocks(self):
        data = "abcddcbaxy"
        ch = utility.chunks(data, 4)
        self.assertEqual("abcd", next(ch))
        self.assertEqual("dcba", next(ch))
        self.assertEqual("xy", next(ch))

    def test_transpose(self):
        data = "abcdabcdabcdab"
        ch = utility.transpose(data, 4)
        self.assertEqual("aaaa", next(ch))
        self.assertEqual("bbbb", next(ch))
        self.assertEqual("ccc", next(ch))
        self.assertEqual("ddd", next(ch))

if __name__ == '__main__':
    unittest.main()
