#!/usr/bin/env python3
'''Minimal UDP transport for SIP requests (VoLTE/IMS access-layer signaling is
predominantly UDP; the framework's send/probe pattern mirrors the PFCP one).'''
import socket

from sip.sip_core.sip_message import parse_response


def send_recv(host, port, data, timeout=3.0, local_port=0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        if local_port:
            sock.bind(('0.0.0.0', local_port))
        sock.sendto(data, (host, port))
        reply, addr = sock.recvfrom(8192)
        return reply, addr
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()


def send(host, port, data):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return sock.sendto(data, (host, port))
    except OSError:
        return 0
    finally:
        sock.close()


def probe(host, port, message, timeout=3.0):
    '''Send a SipMessage and parse a single SIP response, or None.'''
    result = send_recv(host, port, message.get_message(), timeout)
    if result is None:
        return None
    reply, addr = result
    resp = parse_response(reply)
    if resp is not None:
        resp['addr'] = addr[0]
    return resp
