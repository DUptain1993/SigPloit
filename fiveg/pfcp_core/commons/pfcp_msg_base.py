#!/usr/bin/env python3
'''
PFCP message base (TS 29.244 clause 7.2).

PFCP header, node-related variant (S = 0, no SEID):

     8  7  6  5  4  3  2  1
   +--+--+--+--+--+--+--+--+
   |  Version  |Sp|Sp|FO|MP|S|   octet 1
   +--+--+--+--+--+--+--+--+
   |     Message Type      |   octet 2
   +-----------------------+
   |    Message Length     |   octet 3-4
   +-----------------------+
   |   Sequence Number     |   octet 5-7
   +-----------------------+
   |        Spare          |   octet 8
   +-----------------------+

Session-related messages (S = 1) insert an 8-octet SEID between the length and
the sequence number.  The Message Length counts every octet after the first 4.
'''
import struct

from fiveg.pfcp_core.commons import pfcp_commons as C


class PfcpMessageBase(object):

    def __init__(self, msg_type, seid=None, sequence=1):
        if msg_type not in C.PFCPmessageTypeStr:
            raise Exception('invalid PFCP message type: %s' % (msg_type,))
        self.msg_type = int(msg_type)
        # A SEID is present exactly for session-related messages.  Callers may
        # pass seid explicitly; otherwise default to 0 for session messages.
        if seid is None and self.msg_type in C.SESSION_MESSAGE_TYPES:
            seid = 0
        self.seid = seid
        self.sequence = sequence
        self.ies = []

    def add_ie(self, ie):
        if ie is not None:
            self.ies.append(ie)

    def get_packed_ies(self):
        return b''.join(ie.get_packed() for ie in self.ies)

    def _seq_bytes(self):
        # 3-octet sequence number.
        return struct.pack('!L', self.sequence & 0xffffff)[1:]

    def get_message(self):
        payload = self.get_packed_ies()
        s_flag = 1 if self.seid is not None else 0
        octet1 = (C.PFCP_VERSION << 5) | (s_flag & 0x01)

        if s_flag:
            rest = struct.pack('!Q', self.seid & 0xffffffffffffffff)
            rest += self._seq_bytes() + b'\x00' + payload
        else:
            rest = self._seq_bytes() + b'\x00' + payload

        header = struct.pack('!BBH', octet1, self.msg_type, len(rest))
        return header + rest

    def get_msg_type(self):
        return self.msg_type


def parse_header(data):
    '''
    Parse a received PFCP header and return a dict describing it plus the offset
    at which the IE payload starts.  Returns ``None`` if the buffer is too short
    or not PFCP.
    '''
    if data is None or len(data) < 4:
        return None
    octet1 = data[0]
    version = octet1 >> 5
    s_flag = octet1 & 0x01
    msg_type = data[1]
    length = struct.unpack('!H', data[2:4])[0]
    info = {
        'version': version,
        's_flag': s_flag,
        'msg_type': msg_type,
        'msg_type_str': C.PFCPmessageTypeStr.get(msg_type, 'unknown(%d)' % msg_type),
        'length': length,
    }
    if s_flag:
        if len(data) < 16:
            return None
        info['seid'] = struct.unpack('!Q', data[4:12])[0]
        info['sequence'] = int.from_bytes(data[12:15], 'big')
        info['payload_offset'] = 16
    else:
        if len(data) < 8:
            return None
        info['seid'] = None
        info['sequence'] = int.from_bytes(data[4:7], 'big')
        info['payload_offset'] = 8
    return info


def parse_ies(data, offset):
    '''
    Walk the TLV IEs starting at ``offset`` and return a list of
    ``(ie_type, value_bytes)`` tuples.  Grouped IEs are returned as raw bytes.
    '''
    ies = []
    i = offset
    n = len(data)
    while i + 4 <= n:
        ie_type, ie_len = struct.unpack('!HH', data[i:i + 4])
        val = data[i + 4:i + 4 + ie_len]
        ies.append((ie_type, val))
        i += 4 + ie_len
    return ies
