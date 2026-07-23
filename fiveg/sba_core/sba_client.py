#!/usr/bin/env python3
'''
5G Service Based Interface (SBI) client.

5G core network functions expose RESTful services over HTTP/2 (3GPP TS 29.500).
This thin wrapper around ``httpx`` performs the discovery / probing calls used by
the SBA attacks:

  * NRF NF-discovery  (Nnrf_NFDiscovery, TS 29.510)
  * generic authenticated / unauthenticated GET against an NF service endpoint

``httpx`` with the optional ``h2`` package provides real HTTP/2; it is imported
lazily so the rest of SigPloit keeps working even when it is not installed.
'''

# Well-known 5G NF types (TS 29.510 Table 6.1.6.3.3-1, subset).
NF_TYPES = [
    'NRF', 'UDM', 'AMF', 'SMF', 'AUSF', 'NEF', 'PCF', 'SMSF', 'NSSF',
    'UDR', 'UDSF', 'BSF', 'CHF', 'UPF', 'N3IWF', 'GMLC', 'SEPP',
]


class SbaError(Exception):
    pass


def _require_httpx():
    try:
        import httpx  # noqa: F401
        return httpx
    except ImportError:
        raise SbaError(
            "the 'httpx[http2]' package is required for 5G SBA attacks "
            "(pip3 install 'httpx[http2]')")


class SbaClient(object):

    def __init__(self, base_url, token=None, timeout=10.0, verify=False,
                 http2=True):
        '''
        base_url : e.g. "https://nrf.5gc.mnc001.mcc001.3gppnetwork.org:8443"
        token    : optional OAuth2 bearer access token (TS 33.501)
        verify   : TLS certificate verification (off by default for lab targets)
        '''
        httpx = _require_httpx()
        self.base_url = base_url.rstrip('/')
        self.token = token
        self._client = httpx.Client(http2=http2, verify=verify, timeout=timeout)

    def close(self):
        try:
            self._client.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _headers(self, extra=None):
        headers = {'Accept': 'application/json'}
        if self.token:
            headers['Authorization'] = 'Bearer ' + self.token
        if extra:
            headers.update(extra)
        return headers

    def get(self, path, params=None):
        '''Perform a GET against ``base_url + path``. Returns the httpx Response.'''
        url = self.base_url + path if path.startswith('/') else self.base_url + '/' + path
        return self._client.get(url, params=params, headers=self._headers())

    def nf_discover(self, target_nf_type, requester_nf_type='AMF'):
        '''
        Nnrf_NFDiscovery request to an NRF.  Returns the httpx Response; a 200
        with a JSON body listing ``nfInstances`` means the NRF answered the
        discovery query.
        '''
        params = {
            'target-nf-type': target_nf_type,
            'requester-nf-type': requester_nf_type,
        }
        return self.get('/nnrf-disc/v1/nf-instances', params=params)
