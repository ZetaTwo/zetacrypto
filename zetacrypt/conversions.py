__author__ = 'Calle Svensson <calle.svensson@zeta-two.com>'
from builtins import bytes, str, filter, map
from future.utils import tobytes
from six import int2byte
import six
import binascii, base64


def hex_to_bytes(seq):
    """Converts seq from hex string to byte array"""
    return bytearray.fromhex(seq)

def ascii_to_bytes(seq):
    """Converts seq from ASCII string to byte array"""
    return six.iterbytes(seq)

def bytes_to_hex(seq):
    """Converts seq from byte array to hex string"""
    return str(binascii.hexlify(bytes(seq)), 'ascii')

def bytes_to_ascii(seq):
    """Converts seq from byte array to ASCII string"""
    #return ''.join(map(chr, seq))
    return str(seq, 'ascii')

def base64_to_bytes(seq):
    """Converts seq from ASCII base 64 encoding to byte array"""
    return bytes(base64.b64decode(seq))

def bytes_to_base64(seq):
    """Converts seq from byte array to ASCII base 64 encoding"""
    return str(base64.b64encode(seq), 'ascii')

def iterator_to_bytes(seq):
    """Exhausts an iterator an creates a bytes object"""
    return bytes(list(seq))