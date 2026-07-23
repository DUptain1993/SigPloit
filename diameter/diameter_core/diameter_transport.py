#!/usr/bin/env python3
'''
Diameter transport: a length-framed TCP (or SCTP) connection with the RFC 6733
CER/CEA capabilities handshake.

Diameter messages are self-delimiting - octets 1..3 hold the total message
length - so ``recv_message`` reads exactly one message off the stream.
'''
import socket
import struct

from diameter.diameter_core.commons.diameter_msg_base import parse_header
from diameter.diameter_core.commons import avp as A
from diameter.diameter_core.messages.base_messages import (
    capabilities_exchange_request)


def _connect_socket(host, port, use_sctp, timeout):
    if use_sctp:
        try:
            import sctp
            sk = sctp.sctpsocket_tcp(socket.AF_INET)
            sk.settimeout(timeout)
            sk.connect((host, port))
            return sk
        except ImportError:
            # fall back to TCP if pysctp is unavailable
            pass
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sk.settimeout(timeout)
    sk.connect((host, port))
    return sk


class DiameterConnection(object):

    def __init__(self, host, port, origin_host='sigploit.example.com',
                 origin_realm='example.com', host_ip='127.0.0.1',
                 use_sctp=False, timeout=5.0):
        self.host = host
        self.port = port
        self.origin_host = origin_host
        self.origin_realm = origin_realm
        self.host_ip = host_ip
        self.use_sctp = use_sctp
        self.timeout = timeout
        self.sock = None

    def connect(self):
        self.sock = _connect_socket(self.host, self.port, self.use_sctp,
                                    self.timeout)

    def _recv_exact(self, n):
        buf = b''
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def recv_message(self):
        '''Read one full Diameter message; return (header_dict, raw_bytes) or None.'''
        head = self._recv_exact(4)
        if head is None:
            return None
        length = struct.unpack('!I', b'\x00' + head[1:4])[0]
        if length < 20:
            return None
        rest = self._recv_exact(length - 4)
        if rest is None:
            return None
        raw = head + rest
        return parse_header(raw), raw

    def send(self, message):
        self.sock.sendall(message.encode())

    def request(self, message):
        '''Send a request and return (header, avps, raw) of the answer, or None.'''
        self.send(message)
        reply = self.recv_message()
        if reply is None:
            return None
        header, raw = reply
        avps = A.parse_avps(raw, 20)
        return header, avps, raw

    def capabilities_exchange(self):
        '''Perform the CER/CEA handshake; return the CEA (header, avps) or None.'''
        cer = capabilities_exchange_request(self.origin_host, self.origin_realm,
                                            self.host_ip)
        result = self.request(cer)
        if result is None:
            return None
        header, avps, _ = result
        return header, avps

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()
