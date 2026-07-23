#!/usr/bin/env python3
'''
Configuration parser for the PFCP (N4) attacks.

Reads a ``configobj``-style ``.cnf`` file with a ``[GENERIC]`` section (and an
optional ``[SESSION]`` section) - the same convention used by the GTP module's
config files - and exposes the parsed values as plain attributes with sensible
defaults so that attack configs can stay minimal.
'''
from configobj import ConfigObj

from fiveg.pfcp_core.commons import pfcp_commons as C


def _to_int(value, default=0):
    if value is None:
        return default
    try:
        text = str(value).strip()
        return int(text, 16) if text.lower().startswith('0x') else int(text)
    except (ValueError, TypeError):
        return default


class PfcpConfig(object):

    def __init__(self, config_file):
        if not config_file:
            raise Exception('No config file provided')
        cfg = ConfigObj(config_file)
        if 'GENERIC' not in cfg:
            raise Exception('Section GENERIC is required')
        generic = cfg['GENERIC']
        session = cfg['SESSION'] if 'SESSION' in cfg else {}

        # transport / node identity
        self.port = _to_int(generic.get('port'), C.PFCP_UDP_PORT)
        self.node_id = generic.get('node_id', '127.0.0.1')
        self.node_type = _to_int(generic.get('node_type'), C.NODE_ID_IPV4)
        self.sequence = _to_int(generic.get('sequence'), 1)
        self.timeout = _to_int(generic.get('timeout'), 3)

        # session parameters
        self.cp_seid = _to_int(session.get('cp_seid'), 1)
        self.cp_ipv4 = session.get('cp_ipv4', self.node_id)
        self.ue_ipv4 = session.get('ue_ipv4', None)
        self.seid = _to_int(session.get('seid'), 0)
        self.count = _to_int(session.get('count'), 1)

    def get_port(self):
        return self.port
