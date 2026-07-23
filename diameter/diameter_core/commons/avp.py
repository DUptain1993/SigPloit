#!/usr/bin/env python3
'''
Diameter AVP encoding/decoding (RFC 6733 section 4).

AVP wire format:

    +----------------+----------------+
    | AVP Code (4)                    |
    +--------+-----------------------+
    | Flags  | AVP Length (3)         |   Flags: V(0x80) M(0x40) P(0x20)
    +--------+-----------------------+
    | Vendor-ID (4)  (only if V set)  |
    +---------------------------------+
    | Data ... (padded to 4 octets)   |
    +---------------------------------+

AVP Length counts the header + data but NOT the trailing padding.
'''
import socket
import struct

from diameter.diameter_core.commons import diameter_commons as C

FLAG_V = 0x80  # vendor-specific
FLAG_M = 0x40  # mandatory
FLAG_P = 0x20  # protected


def _pad4(data):
    rem = len(data) % 4
    return data + (b'\x00' * (4 - rem)) if rem else data


class AVP(object):

    def __init__(self, code, data=b'', vendor_id=0, mandatory=True):
        self.code = code
        self.vendor_id = vendor_id
        self.mandatory = mandatory
        self.data = data if isinstance(data, (bytes, bytearray)) else bytes(data)

    def encode(self):
        flags = 0
        if self.mandatory:
            flags |= FLAG_M
        header_len = 8 + (4 if self.vendor_id else 0)
        length = header_len + len(self.data)
        out = struct.pack('!I', self.code)
        if self.vendor_id:
            flags |= FLAG_V
        out += struct.pack('!B', flags)
        out += struct.pack('!I', length)[1:]        # 3-byte length
        if self.vendor_id:
            out += struct.pack('!I', self.vendor_id)
        out += self.data
        return _pad4(out)


# --- typed AVP constructors -------------------------------------------------
def utf8(code, value, vendor_id=0, mandatory=True):
    return AVP(code, value.encode('utf-8'), vendor_id, mandatory)


def octetstring(code, value, vendor_id=0, mandatory=True):
    if isinstance(value, str):
        value = value.encode('latin-1')
    return AVP(code, value, vendor_id, mandatory)


def unsigned32(code, value, vendor_id=0, mandatory=True):
    return AVP(code, struct.pack('!I', value & 0xffffffff), vendor_id, mandatory)


def integer32(code, value, vendor_id=0, mandatory=True):
    return AVP(code, struct.pack('!i', value), vendor_id, mandatory)


def grouped(code, avps, vendor_id=0, mandatory=True):
    return AVP(code, b''.join(a.encode() for a in avps), vendor_id, mandatory)


def address(code, ip, vendor_id=0, mandatory=True):
    '''Diameter Address = 2-byte AddressType (1 = IPv4) + address bytes.'''
    data = struct.pack('!H', 1) + socket.inet_aton(ip)
    return AVP(code, data, vendor_id, mandatory)


def parse_avps(data, offset=0):
    '''
    Walk AVPs in ``data`` starting at ``offset``; return a list of dicts with
    code, vendor_id, flags and raw value bytes.  Grouped AVPs are returned raw.
    '''
    avps = []
    i = offset
    n = len(data)
    while i + 8 <= n:
        code = struct.unpack('!I', data[i:i + 4])[0]
        flags = data[i + 4]
        length = struct.unpack('!I', b'\x00' + data[i + 5:i + 8])[0]
        if length < 8 or i + length > n:
            break
        vendor_id = 0
        val_off = i + 8
        if flags & FLAG_V:
            vendor_id = struct.unpack('!I', data[i + 8:i + 12])[0]
            val_off = i + 12
        value = data[val_off:i + length]
        avps.append({'code': code, 'vendor_id': vendor_id, 'flags': flags,
                     'value': value})
        # advance past padding
        i += length + ((4 - length % 4) % 4)
    return avps


def find_avp(avps, code, vendor_id=0):
    for a in avps:
        if a['code'] == code and a['vendor_id'] == vendor_id:
            return a
    return None
