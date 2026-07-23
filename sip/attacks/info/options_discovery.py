#!/usr/bin/env python3
'''
SIP OPTIONS Node Discovery (IMS/VoLTE access layer).

OPTIONS is the SIP equivalent of a ping: a well-formed OPTIONS to a P-CSCF/
S-CSCF/IMS core address typically gets a 200 OK (or a 4xx that still proves the
node is alive) without establishing a dialog.  The response also frequently
discloses the node's software via the User-Agent/Server header.

    main(config_file, remote_net, listening, verbosity, output_file)
'''
import csv

from IPy import IP

from sip.sip_core.sip_config_parser import SipConfig
from sip.sip_core.sip_message import build_request
from sip.sip_core.sip_transport import probe
from sip.commons.utilities import logOk, logErr, logWarn, logInfo, logNormal

TAG = 'SIP-DISCOVERY'


def _targets(remote_net):
    try:
        return [ip.strNormal() for ip in IP(remote_net)]
    except (ValueError, TypeError):
        return [remote_net]


def _write_results(output_file, rows):
    if not output_file or not rows:
        return
    try:
        with open(output_file, 'w', newline='') as fh:
            writer = csv.writer(fh)
            writer.writerow(['host', 'port', 'status', 'reason', 'server'])
            writer.writerows(rows)
        logOk('Results written to %s' % output_file, TAG=TAG)
    except OSError as e:
        logErr('Could not write results file: %s' % e, TAG=TAG)


def main(config_file, remote_net, listening=True, verbosity=2,
         output_file='sip_nodes.csv'):
    if not remote_net:
        logErr('No target set. Use "set target <ip|cidr>".', TAG=TAG)
        return
    try:
        cfg = SipConfig(config_file)
    except Exception as e:
        logWarn('Config not loaded (%s); using defaults.' % e, TAG=TAG)
        cfg = SipConfig()

    verbose = verbosity >= 2
    hosts = _targets(remote_net)
    logInfo('Probing %d target(s) on SIP/UDP %d ...' % (len(hosts), cfg.port),
            TAG=TAG)

    found = []
    for host in hosts:
        req = build_request(
            'OPTIONS', 'sip:%s' % host, 'sip:%s@%s' % (cfg.from_user, cfg.local_host),
            'sip:%s' % host, cfg.local_host, local_port=cfg.local_port or 5060)
        logNormal('-> %s : OPTIONS' % host, verbose=verbose, TAG=TAG)
        resp = probe(host, cfg.port, req, timeout=cfg.timeout)
        if resp is not None:
            server = resp['headers'].get('server') or resp['headers'].get('user-agent') or ''
            logOk('%s is a live SIP node  [%d %s]  server=%s'
                  % (host, resp['status_code'], resp['reason'], server or '-'), TAG=TAG)
            found.append([host, cfg.port, resp['status_code'], resp['reason'], server])
        else:
            logNormal('%s no SIP response' % host, verbose=verbose, TAG=TAG)

    if found:
        logWarn('%d SIP node(s) reachable. Recommendation: restrict access-layer '
                'SIP signaling to legitimate P-CSCF/registered UEs and disable '
                'Server/User-Agent version disclosure.' % len(found), TAG=TAG)
        _write_results(output_file, found)
    else:
        logInfo('No SIP nodes responded on the target(s).', TAG=TAG)
    return found
