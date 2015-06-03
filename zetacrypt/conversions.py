__author__ = 'Calle Svensson <calle.svensson@zeta-two.com>'
import binascii


def hex_to_ascii(seq):
    """Converts seq from hex string to ASCII string"""
    return seq.decode("hex")


def ascii_to_hex(seq):
    """Converts seq from ASCII string to hex string"""
    return seq.encode("hex")


def hex_to_byte(seq):
    """Converts seq from hex string to byte array"""
    return map(ord, binascii.unhexlify(seq))


def byte_to_hex(seq):
    """Converts seq from byte array to hex string"""
    return binascii.hexlify(bytearray(seq))


def ascii_to_byte(seq):
    """Converts seq from ASCII string to byte array"""
    return map(ord, seq)


def byte_to_ascii(seq):
    """Converts seq from byte array to ASCII string"""
    return ''.join(map(chr, seq))
