__author__ = 'Calle'


def readfile(path):
    with open(path, 'r') as datafile:
        res = datafile.read()
    return res
