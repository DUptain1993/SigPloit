#!/usr/bin/env python3
'''
Configuration parser for the Diameter (S6a) attacks - configobj ``.cnf`` with a
``[GENERIC]`` section (peer/identity) and an ``[IES]`` section (subscriber).
'''
from configobj import ConfigObj

from diameter.diameter_core.commons import diameter_commons as C


def _to_int(value, default=0):
    if value is None:
        return default
    try:
        text = str(value).strip()
        return int(text, 16) if text.lower().startswith('0x') else int(text)
    except (ValueError, TypeError):
        return default


class DiameterConfig(object):

    def __init__(self, config_file=None):
        g = {}
        ies = {}
        if config_file:
            cfg = ConfigObj(config_file)
            if 'GENERIC' not in cfg:
                raise Exception('Section GENERIC is required')
            g = cfg['GENERIC']
            ies = cfg['IES'] if 'IES' in cfg else {}

        # transport / local identity
        self.port = _to_int(g.get('port'), C.DIAMETER_TCP_PORT)
        self.use_sctp = str(g.get('use_sctp', 'false')).lower() in ('1', 'true', 'yes')
        self.origin_host = g.get('origin_host', 'sigploit.example.com')
        self.origin_realm = g.get('origin_realm', 'example.com')
        self.host_ip = g.get('host_ip', '127.0.0.1')
        self.timeout = float(_to_int(g.get('timeout'), 5))

        # peer (HSS) identity
        self.dest_host = g.get('dest_host', None) or None
        self.dest_realm = g.get('dest_realm', 'epc.mnc001.mcc001.3gppnetwork.org')

        # subscriber / IES
        self.imsi = ies.get('imsi', '001010000000001')
        self.mcc = ies.get('mcc', '001')
        self.mnc = ies.get('mnc', '01')
        self.num_vectors = _to_int(ies.get('num_vectors'), 1)
        self.count = _to_int(ies.get('count'), 1)

    def get_port(self):
        return self.port
