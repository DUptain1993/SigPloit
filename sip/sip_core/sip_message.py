#!/usr/bin/env python3
'''
SIP message builder / parser (RFC 3261), for the IMS/VoLTE access-layer attacks.

SIP is a plain-text, line-oriented protocol:

    METHOD sip:user@host SIP/2.0\\r\\n
    Header: value\\r\\n
    ...
    \\r\\n
    [body]

This module builds request messages as ``bytes`` (CRLF-terminated, as the wire
format requires) and parses status-line + headers from a response.
'''
import random
import string
import time

SIP_VERSION = 'SIP/2.0'


def _rand_token(n=10):
    return ''.join(random.choice(string.ascii_lowercase + string.digits)
                   for _ in range(n))


def make_branch():
    return 'z9hG4bK' + _rand_token(12)   # RFC 3261 magic cookie prefix


def make_call_id(host):
    return '%s@%s' % (_rand_token(16), host)


def make_tag():
    return _rand_token(8)


class SipMessage(object):
    '''Builds a single SIP request as CRLF-terminated bytes.'''

    def __init__(self, method, request_uri, headers=None, body=b''):
        self.method = method
        self.request_uri = request_uri
        self.headers = list(headers) if headers else []   # [(name, value), ...]
        self.body = body if isinstance(body, (bytes, bytearray)) else body.encode('utf-8')

    def add_header(self, name, value):
        self.headers.append((name, value))
        return self

    def get_message(self):
        lines = ['%s %s %s' % (self.method, self.request_uri, SIP_VERSION)]
        for name, value in self.headers:
            lines.append('%s: %s' % (name, value))
        if 'Content-Length' not in [h[0] for h in self.headers]:
            lines.append('Content-Length: %d' % len(self.body))
        text = '\r\n'.join(lines) + '\r\n\r\n'
        return text.encode('utf-8') + self.body


def build_request(method, request_uri, from_uri, to_uri, local_host,
                  local_port=5060, call_id=None, cseq=1, branch=None,
                  from_tag=None, extra_headers=None, max_forwards=70,
                  contact=None, body=b''):
    '''
    Build a standalone (out-of-dialog) SIP request with the mandatory headers:
    Via, From, To, Call-ID, CSeq, Max-Forwards.
    '''
    branch = branch or make_branch()
    from_tag = from_tag or make_tag()
    call_id = call_id or make_call_id(local_host)

    msg = SipMessage(method, request_uri)
    msg.add_header('Via', 'SIP/2.0/UDP %s:%d;branch=%s' % (local_host, local_port, branch))
    msg.add_header('Max-Forwards', str(max_forwards))
    msg.add_header('From', '<%s>;tag=%s' % (from_uri, from_tag))
    msg.add_header('To', '<%s>' % to_uri)
    msg.add_header('Call-ID', call_id)
    msg.add_header('CSeq', '%d %s' % (cseq, method))
    if contact:
        msg.add_header('Contact', '<%s>' % contact)
    msg.add_header('User-Agent', 'SigPloit')
    if extra_headers:
        for name, value in extra_headers:
            msg.add_header(name, value)
    msg.body = body if isinstance(body, (bytes, bytearray)) else body.encode('utf-8')
    return msg


def parse_response(data):
    '''
    Parse a SIP response: return a dict with status_code, reason, headers (dict
    of lowercased name -> value; repeated headers keep the last value) and body,
    or ``None`` if the buffer isn't a SIP status line.
    '''
    if not data:
        return None
    try:
        text = data.decode('utf-8', 'replace')
    except Exception:
        return None
    if '\r\n\r\n' in text:
        head, body = text.split('\r\n\r\n', 1)
    else:
        head, body = text, ''
    lines = head.split('\r\n')
    if not lines or not lines[0].startswith('SIP/2.0'):
        return None
    parts = lines[0].split(' ', 2)
    if len(parts) < 2:
        return None
    status_code = int(parts[1])
    reason = parts[2] if len(parts) > 2 else ''
    headers = {}
    for line in lines[1:]:
        if ':' in line:
            name, _, value = line.partition(':')
            headers[name.strip().lower()] = value.strip()
    return {'status_code': status_code, 'reason': reason, 'headers': headers,
           'body': body, 'raw': data}
