#!/usr/bin/env python3
'''
Minimal UDP transport for PFCP.

PFCP is a simple request/response protocol over UDP 8805, so a synchronous
"send one datagram, wait for one reply" helper is enough for the discovery and
session attacks.  All functions work in terms of ``bytes``.
'''
import socket

from fiveg.pfcp_core.commons.pfcp_msg_base import parse_header, parse_ies


def send_recv(host, port, data, timeout=3.0):
    '''
    Send ``data`` to ``host:port`` and wait up to ``timeout`` seconds for a
    single reply.  Returns ``(reply_bytes, addr)`` or ``None`` on timeout /
    error.
    '''
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(data, (host, port))
        reply, addr = sock.recvfrom(4096)
        return reply, addr
    except socket.timeout:
        return None
    except OSError:
        return None
    finally:
        sock.close()


def send(host, port, data):
    '''Fire-and-forget a single PFCP datagram. Returns bytes sent.'''
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return sock.sendto(data, (host, port))
    except OSError:
        return 0
    finally:
        sock.close()


def probe(host, port, message, timeout=3.0):
    '''
    Send a PFCP ``message`` object (anything with ``get_message()``) and, if a
    reply arrives, parse its header + IEs.  Returns a dict describing the reply
    or ``None``.
    '''
    result = send_recv(host, port, message.get_message(), timeout)
    if result is None:
        return None
    reply, addr = result
    header = parse_header(reply)
    if header is None:
        return None
    header['addr'] = addr[0]
    header['ies'] = parse_ies(reply, header['payload_offset'])
    header['raw'] = reply
    return header
