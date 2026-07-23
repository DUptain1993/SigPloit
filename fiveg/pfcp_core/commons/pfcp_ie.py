#!/usr/bin/env python3
'''
PFCP Information Elements (TS 29.244 clause 8).

Every PFCP IE is TLV encoded as:

    +--------+--------+----------------+
    | Type   | Length | Value          |
    | 2 oct  | 2 oct  | <Length> oct   |
    +--------+--------+----------------+

Grouped IEs (Create PDR, Create FAR, PDI, ...) simply carry other IEs as their
value.  All ``get_packed()`` methods return ``bytes``.
'''
import socket
import struct
import time

from fiveg.pfcp_core.commons import pfcp_commons as C


class PfcpIE(object):
    '''Base class for all PFCP information elements.'''

    def __init__(self, ie_type):
        self.ie_type = ie_type

    def _get_val(self):
        '''Return the IE value as ``bytes`` (overridden by subclasses).'''
        return b''

    def get_packed(self):
        val = self._get_val()
        return struct.pack('!HH', self.ie_type, len(val)) + val


class GroupedIE(PfcpIE):
    '''An IE whose value is a concatenation of child IEs.'''

    def __init__(self, ie_type, children=None):
        PfcpIE.__init__(self, ie_type)
        self.children = list(children) if children else []

    def add(self, ie):
        if ie is not None:
            self.children.append(ie)
        return self

    def _get_val(self):
        return b''.join(child.get_packed() for child in self.children)


class NodeID(PfcpIE):
    '''Node ID (type 60): identifies the sending PFCP node.'''

    def __init__(self, value='127.0.0.1', node_type=C.NODE_ID_IPV4):
        PfcpIE.__init__(self, C.PFCP_IE['node-id'])
        self.value = value
        self.node_type = node_type

    def _get_val(self):
        if self.node_type == C.NODE_ID_IPV4:
            body = socket.inet_aton(self.value)
        elif self.node_type == C.NODE_ID_IPV6:
            body = socket.inet_pton(socket.AF_INET6, self.value)
        else:
            body = self.value.encode('latin-1')
        return struct.pack('!B', self.node_type & 0x0f) + body


class RecoveryTimeStamp(PfcpIE):
    '''Recovery Time Stamp (type 96): NTP-format restart counter.'''

    def __init__(self, ntp_seconds=None):
        PfcpIE.__init__(self, C.PFCP_IE['recovery-time-stamp'])
        if ntp_seconds is None:
            ntp_seconds = int(time.time()) + C.NTP_EPOCH_OFFSET
        self.ntp_seconds = ntp_seconds

    def _get_val(self):
        return struct.pack('!L', self.ntp_seconds & 0xffffffff)


class Cause(PfcpIE):
    '''Cause (type 19): single-octet result code.'''

    def __init__(self, cause=C.PFCP_CAUSE['request-accepted']):
        PfcpIE.__init__(self, C.PFCP_IE['cause'])
        self.cause = cause

    def _get_val(self):
        return struct.pack('!B', self.cause & 0xff)


class FSEID(PfcpIE):
    '''F-SEID (type 57): fully-qualified SEID with node address(es).'''

    def __init__(self, seid, ipv4=None, ipv6=None):
        PfcpIE.__init__(self, C.PFCP_IE['f-seid'])
        self.seid = seid
        self.ipv4 = ipv4
        self.ipv6 = ipv6

    def _get_val(self):
        flags = 0
        if self.ipv4:
            flags |= 0x02  # V4 flag (bit 2)
        if self.ipv6:
            flags |= 0x01  # V6 flag (bit 1)
        out = struct.pack('!B', flags) + struct.pack('!Q', self.seid & 0xffffffffffffffff)
        if self.ipv4:
            out += socket.inet_aton(self.ipv4)
        if self.ipv6:
            out += socket.inet_pton(socket.AF_INET6, self.ipv6)
        return out


class PDRID(PfcpIE):
    '''PDR ID (type 56): 2-octet rule identifier.'''

    def __init__(self, rule_id):
        PfcpIE.__init__(self, C.PFCP_IE['pdr-id'])
        self.rule_id = rule_id

    def _get_val(self):
        return struct.pack('!H', self.rule_id & 0xffff)


class FARID(PfcpIE):
    '''FAR ID (type 108): 4-octet rule identifier.'''

    def __init__(self, rule_id):
        PfcpIE.__init__(self, C.PFCP_IE['far-id'])
        self.rule_id = rule_id

    def _get_val(self):
        return struct.pack('!L', self.rule_id & 0xffffffff)


class Precedence(PfcpIE):
    '''Precedence (type 29): 4-octet rule precedence.'''

    def __init__(self, precedence=255):
        PfcpIE.__init__(self, C.PFCP_IE['precedence'])
        self.precedence = precedence

    def _get_val(self):
        return struct.pack('!L', self.precedence & 0xffffffff)


class SourceInterface(PfcpIE):
    '''Source Interface (type 20): access/core/SGi-N6/CP indicator.'''

    def __init__(self, interface=C.SRC_IFACE_ACCESS):
        PfcpIE.__init__(self, C.PFCP_IE['source-interface'])
        self.interface = interface

    def _get_val(self):
        return struct.pack('!B', self.interface & 0x0f)


class ApplyAction(PfcpIE):
    '''Apply Action (type 44): forwarding action bit flags.'''

    def __init__(self, action=C.APPLY_ACTION_FORW):
        PfcpIE.__init__(self, C.PFCP_IE['apply-action'])
        self.action = action

    def _get_val(self):
        return struct.pack('!B', self.action & 0xff)


class UEIPAddress(PfcpIE):
    '''UE IP Address (type 93).'''

    def __init__(self, ipv4=None, ipv6=None, source=True):
        PfcpIE.__init__(self, C.PFCP_IE['ue-ip-address'])
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.source = source

    def _get_val(self):
        flags = 0
        if self.ipv6:
            flags |= 0x01  # V6
        if self.ipv4:
            flags |= 0x02  # V4
        if self.source:
            flags |= 0x04  # S/D flag: source address
        out = struct.pack('!B', flags)
        if self.ipv4:
            out += socket.inet_aton(self.ipv4)
        if self.ipv6:
            out += socket.inet_pton(socket.AF_INET6, self.ipv6)
        return out


def create_pdi(source_interface=C.SRC_IFACE_ACCESS, ue_ipv4=None):
    '''Build a PDI grouped IE (type 2) carrying a Source Interface.'''
    pdi = GroupedIE(C.PFCP_IE['pdi'])
    pdi.add(SourceInterface(source_interface))
    if ue_ipv4:
        pdi.add(UEIPAddress(ipv4=ue_ipv4))
    return pdi


def create_pdr(pdr_id=1, precedence=255, source_interface=C.SRC_IFACE_ACCESS,
               ue_ipv4=None):
    '''Build a Create PDR grouped IE (type 1).'''
    pdr = GroupedIE(C.PFCP_IE['create-pdr'])
    pdr.add(PDRID(pdr_id))
    pdr.add(Precedence(precedence))
    pdr.add(create_pdi(source_interface, ue_ipv4))
    return pdr


def create_far(far_id=1, action=C.APPLY_ACTION_FORW):
    '''Build a Create FAR grouped IE (type 3).'''
    far = GroupedIE(C.PFCP_IE['create-far'])
    far.add(FARID(far_id))
    far.add(ApplyAction(action))
    return far
