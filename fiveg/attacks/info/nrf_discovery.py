#!/usr/bin/env python3
'''
NRF NF-Discovery (5G SBI / HTTP2).

The NRF (Network Repository Function) is the "phone book" of the 5G core.  Its
Nnrf_NFDiscovery service (TS 29.510) returns the profiles - including IP/FQDN
addresses - of registered network functions.  If it answers discovery queries
without a valid OAuth2 access token, an attacker who can reach the SBI can map
the entire core.

    main(config_file, target, listening, verbosity, output_file)
'''
import csv

from fiveg.sba_core.sba_config_parser import SbaConfig
from fiveg.sba_core.sba_client import SbaClient, SbaError, NF_TYPES
from fiveg.commons.utilities import logOk, logErr, logWarn, logInfo, logNormal

TAG = 'NRF-DISCOVERY'


def _count_instances(response):
    try:
        body = response.json()
    except ValueError:
        return None
    if isinstance(body, dict):
        return len(body.get('nfInstances', []))
    return None


def main(config_file, target, listening=True, verbosity=2,
         output_file='nrf_nfs.csv'):
    if not config_file and not target:
        logErr('Set a config file ("set config <file>") describing the NRF.',
               TAG=TAG)
        return

    try:
        if config_file:
            cfg = SbaConfig(config_file)
            base_url = cfg.base_url()
            token = cfg.token
            requester = cfg.requester_nf_type
            verify = cfg.verify_tls
            timeout = cfg.timeout
        else:
            base_url = target if '://' in target else 'https://' + target
            token = None
            requester = 'AMF'
            verify = False
            timeout = 10.0
    except Exception as e:
        logErr('Bad config: %s' % e, TAG=TAG)
        return

    verbose = verbosity >= 2
    logInfo('Querying NRF %s (token=%s) ...'
            % (base_url, 'yes' if token else 'none'), TAG=TAG)

    rows = []
    unauth_hit = False
    try:
        client = SbaClient(base_url, token=token, verify=verify, timeout=timeout)
    except SbaError as e:
        logErr(str(e), TAG=TAG)
        return

    try:
        for nf_type in NF_TYPES:
            try:
                resp = client.nf_discover(nf_type, requester_nf_type=requester)
            except Exception as e:
                logNormal('%s: request failed (%s)' % (nf_type, e),
                          verbose=verbose, TAG=TAG)
                continue
            count = _count_instances(resp)
            if resp.status_code == 200 and count is not None:
                logOk('%-6s -> %d instance(s) disclosed by NRF' % (nf_type, count),
                      TAG=TAG)
                rows.append([nf_type, resp.status_code, count])
                if not token:
                    unauth_hit = True
            else:
                logNormal('%-6s -> HTTP %s' % (nf_type, resp.status_code),
                          verbose=verbose, TAG=TAG)
    finally:
        client.close()

    if rows:
        _write_results(output_file, rows)
    if unauth_hit:
        logWarn('NRF disclosed NF profiles WITHOUT an access token. '
                'Recommendation: enforce OAuth2 (TS 33.501) on all NRF service '
                'operations and restrict SBI reachability (SEPP/PLMN isolation).',
                TAG=TAG)
    elif not rows:
        logInfo('NRF returned no NF instances (or denied the queries).', TAG=TAG)
    return rows


def _write_results(output_file, rows):
    if not output_file or not rows:
        return
    try:
        with open(output_file, 'w', newline='') as fh:
            writer = csv.writer(fh)
            writer.writerow(['nf_type', 'http_status', 'instances'])
            writer.writerows(rows)
        logOk('Results written to %s' % output_file, TAG=TAG)
    except OSError as e:
        logErr('Could not write results file: %s' % e, TAG=TAG)
