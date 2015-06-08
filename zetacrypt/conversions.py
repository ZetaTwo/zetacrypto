__author__ = 'Calle Svensson <calle.svensson@zeta-two.com>'
import binascii, base64


def hex_to_bytes(seq):
    """Converts seq from hex string to byte array"""
    return binascii.unhexlify(bytes(seq, 'ascii'))

def ascii_to_bytes(seq):
    """Converts seq from ASCII string to byte array"""
    return bytes(seq, 'ascii')

def bytes_to_hex(seq):
    """Converts seq from byte array to hex string"""
    return str(binascii.hexlify(bytes(seq)), 'ascii')

def bytes_to_ascii(seq):
    """Converts seq from byte array to ASCII string"""
    return ''.join(map(chr, seq))

def base64_to_bytes(seq):
    """Converts seq from ASCII base 64 encoding to byte array"""
    return base64.b64decode(bytes(seq,'ascii'))

def bytes_to_base64(seq):
    """Converts seq from byte array to ASCII base 64 encoding"""
    return str(base64.b64encode(seq), 'ascii')
