#!/usr/bin/env python3
'''
Configuration parser for the 5G SBA (SBI/HTTP2) attacks.
'''
from configobj import ConfigObj


class SbaConfig(object):

    def __init__(self, config_file):
        if not config_file:
            raise Exception('No config file provided')
        cfg = ConfigObj(config_file)
        if 'GENERIC' not in cfg:
            raise Exception('Section GENERIC is required')
        generic = cfg['GENERIC']

        self.scheme = generic.get('scheme', 'https')
        self.host = generic.get('host', '127.0.0.1')
        self.port = generic.get('port', '8443')
        self.token = generic.get('token', None) or None
        self.requester_nf_type = generic.get('requester_nf_type', 'AMF')
        self.target_nf_type = generic.get('target_nf_type', None) or None
        # optional explicit service path for the NF-access probe
        self.service_path = generic.get('service_path', '/nnrf-disc/v1/nf-instances')
        try:
            self.timeout = float(generic.get('timeout', 10))
        except (ValueError, TypeError):
            self.timeout = 10.0
        self.verify_tls = str(generic.get('verify_tls', 'false')).lower() in (
            '1', 'true', 'yes')

    def base_url(self):
        return '%s://%s:%s' % (self.scheme, self.host, self.port)
