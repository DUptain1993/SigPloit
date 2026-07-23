#!/usr/bin/env python3
'''
Diameter message base (RFC 6733 section 3).

Diameter header (20 octets):

    +--------+-----------------------+
    | Ver(1) | Message Length (3)    |
    +--------+-----------------------+
    | Flags  | Command Code (3)      |   Flags: R(0x80) P(0x40) E(0x20) T(0x10)
    +--------+-----------------------+
    | Application-ID (4)             |
    +--------------------------------+
    | Hop-by-Hop Identifier (4)      |
    +--------------------------------+
    | End-to-End Identifier (4)      |
    +--------------------------------+
    | AVPs ...                       |
    +--------------------------------+
'''
import random
import struct

from diameter.diameter_core.commons import diameter_commons as C


def _new_id():
    return random.getrandbits(32)


class DiameterMessage(object):

    def __init__(self, command_code, application_id=0, request=True,
                 hop_by_hop=None, end_to_end=None, proxiable=False):
        self.command_code = command_code
        self.application_id = application_id
        self.request = request
        self.proxiable = proxiable
        self.hop_by_hop = _new_id() if hop_by_hop is None else hop_by_hop
        self.end_to_end = _new_id() if end_to_end is None else end_to_end
        self.avps = []

    def add(self, avp):
        if avp is not None:
            self.avps.append(avp)
        return self

    def add_all(self, avps):
        for a in avps:
            self.add(a)
        return self

    def _command_flags(self):
        flags = 0
        if self.request:
            flags |= C.FLAG_REQUEST
        if self.proxiable:
            flags |= C.FLAG_PROXIABLE
        return flags

    def encode(self):
        body = b''.join(a.encode() for a in self.avps)
        length = 20 + len(body)
        out = struct.pack('!B', C.DIAMETER_VERSION)
        out += struct.pack('!I', length)[1:]                 # 3-byte length
        out += struct.pack('!B', self._command_flags())
        out += struct.pack('!I', self.command_code)[1:]      # 3-byte cmd code
        out += struct.pack('!I', self.application_id)
        out += struct.pack('!I', self.hop_by_hop)
        out += struct.pack('!I', self.end_to_end)
        out += body
        return out

    # alias so attacks read like the GTP/PFCP ones
    def get_message(self):
        return self.encode()


def parse_header(data):
    '''Parse a Diameter header; return a dict or None if too short/invalid.'''
    if data is None or len(data) < 20:
        return None
    version = data[0]
    length = struct.unpack('!I', b'\x00' + data[1:4])[0]
    flags = data[4]
    command_code = struct.unpack('!I', b'\x00' + data[5:8])[0]
    application_id, hop_by_hop, end_to_end = struct.unpack('!III', data[8:20])
    return {
        'version': version,
        'length': length,
        'flags': flags,
        'request': bool(flags & C.FLAG_REQUEST),
        'error': bool(flags & C.FLAG_ERROR),
        'command_code': command_code,
        'command_name': C.CMD_NAME.get(command_code, 'Command-%d' % command_code),
        'application_id': application_id,
        'hop_by_hop': hop_by_hop,
        'end_to_end': end_to_end,
    }
