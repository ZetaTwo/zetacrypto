__author__ = 'Calle Svensson <calle.svensson@zeta-two.com>'
import binascii


def hex_to_bytes(seq):
    """Converts seq from hex string to byte array"""
    return binascii.unhexlify(bytes(seq, 'ascii'))

def ascii_to_bytes(seq):
    """Converts seq from ASCII string to byte array"""
    return bytes(seq, 'ascii')

def bytes_to_hex(seq):
    """Converts seq from byte array to hex string"""
    return str(binascii.hexlify(seq), 'ascii')

def bytes_to_ascii(seq):
    """Converts seq from byte array to ASCII string"""
    return ''.join(map(chr, seq))
