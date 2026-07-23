#!/usr/bin/env python3
'''Configuration parser for the SIP (IMS/VoLTE) attacks.'''
from configobj import ConfigObj


def _to_int(value, default=0):
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


class SipConfig(object):

    def __init__(self, config_file=None):
        g = {}
        if config_file:
            cfg = ConfigObj(config_file)
            if 'GENERIC' not in cfg:
                raise Exception('Section GENERIC is required')
            g = cfg['GENERIC']

        self.port = _to_int(g.get('port'), 5060)
        self.local_host = g.get('local_host', '10.0.0.1')
        self.local_port = _to_int(g.get('local_port'), 0)
        self.domain = g.get('domain', 'ims.mnc001.mcc001.3gppnetwork.org')
        self.from_user = g.get('from_user', 'sigploit')
        self.to_user = g.get('to_user', '1000')
        self.spoofed_user = g.get('spoofed_user', None) or None
        self.ext_start = _to_int(g.get('ext_start'), 1000)
        self.ext_end = _to_int(g.get('ext_end'), 1010)
        self.count = _to_int(g.get('count'), 100)
        self.timeout = float(_to_int(g.get('timeout'), 3))

    def get_port(self):
        return self.port
