__author__ = 'Calle Svensson <calle.svensson@zeta-two.com>'


def readfile(path):
    with open(path, 'r') as datafile:
        res = datafile.read()
    return res


def chunks(seq, size):
    num_blocks = (len(seq) + size - 1) // size
    for i in range(num_blocks):
        yield seq[i * size:(i + 1) * size]

def transpose(seq, size):
    for i in range(size):
        yield seq[i::size]