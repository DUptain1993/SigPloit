#!/usr/bin/env python3
'''
PFCP Node Discovery (5G N4 interface).

Sweeps a target host or subnet with PFCP Heartbeat Requests (and, optionally,
Association Setup Requests) and reports which hosts answer - i.e. which are live
PFCP nodes (UPF / SMF).  Exposure of N4 to a reachable network is itself the
finding: N4 must stay on an isolated, access-controlled segment.

Entry point mirrors the GTP attacks:
    main(config_file, remote_net, listening, verbosity, output_file)
'''
import csv

from IPy import IP

from fiveg.pfcp_core.pfcp_config_parser import PfcpConfig
from fiveg.pfcp_core.pfcp_transport import probe
from fiveg.pfcp_core.node_messages.heartbeat import HeartbeatRequest
from fiveg.pfcp_core.node_messages.association import AssociationSetupRequest
from fiveg.pfcp_core.commons import pfcp_commons as C
from fiveg.commons.utilities import logOk, logErr, logWarn, logInfo, logNormal

TAG = 'PFCP-DISCOVERY'


def _targets(remote_net):
    try:
        return [ip.strNormal() for ip in IP(remote_net)]
    except (ValueError, TypeError):
        # Plain hostname / single address that IPy cannot parse as a network.
        return [remote_net]


def _write_results(output_file, rows):
    if not output_file or not rows:
        return
    try:
        with open(output_file, 'w', newline='') as fh:
            writer = csv.writer(fh)
            writer.writerow(['host', 'port', 'message', 'node_id', 'recovery'])
            writer.writerows(rows)
        logOk('Results written to %s' % output_file, TAG=TAG)
    except OSError as e:
        logErr('Could not write results file: %s' % e, TAG=TAG)


def _decode_node(ies):
    '''Pull a Node ID / Recovery Time Stamp out of parsed IEs for reporting.'''
    node_id = recovery = ''
    for ie_type, val in ies:
        if ie_type == C.PFCP_IE['node-id'] and len(val) >= 1:
            nt = val[0] & 0x0f
            body = val[1:]
            if nt == C.NODE_ID_IPV4 and len(body) >= 4:
                node_id = '.'.join(str(b) for b in body[:4])
            elif nt == C.NODE_ID_FQDN:
                node_id = body.decode('latin-1', 'replace')
            else:
                node_id = body.hex()
        elif ie_type == C.PFCP_IE['recovery-time-stamp'] and len(val) >= 4:
            recovery = str(int.from_bytes(val[:4], 'big'))
    return node_id, recovery


def main(config_file, remote_net, listening=True, verbosity=2,
         output_file='pfcp_nodes.csv'):
    if not remote_net:
        logErr('No target set. Use "set target <ip|cidr>".', TAG=TAG)
        return

    port = C.PFCP_UDP_PORT
    node_id = '127.0.0.1'
    node_type = C.NODE_ID_IPV4
    timeout = 3
    if config_file:
        try:
            cfg = PfcpConfig(config_file)
            port, node_id, node_type, timeout = (
                cfg.port, cfg.node_id, cfg.node_type, cfg.timeout)
        except Exception as e:
            logWarn('Config not loaded (%s); using defaults.' % e, TAG=TAG)

    verbose = verbosity >= 2
    targets = _targets(remote_net)
    logInfo('Probing %d target(s) on PFCP/UDP %d ...' % (len(targets), port),
            TAG=TAG)

    found = []
    for host in targets:
        replied = False
        for maker in (HeartbeatRequest(), AssociationSetupRequest(
                node_id=node_id, node_type=node_type)):
            logNormal('-> %s : %s' % (host, C.PFCPmessageTypeStr[maker.get_msg_type()]),
                      verbose=verbose, TAG=TAG)
            reply = probe(host, port, maker, timeout=timeout)
            if reply is not None:
                nid, rec = _decode_node(reply['ies'])
                logOk('%s is a live PFCP node  [%s]  node_id=%s recovery=%s'
                      % (host, reply['msg_type_str'], nid or '-', rec or '-'),
                      TAG=TAG)
                found.append([host, port, reply['msg_type_str'], nid, rec])
                replied = True
                break
        if not replied:
            logNormal('%s no PFCP response' % host, verbose=verbose, TAG=TAG)

    if found:
        logWarn('%d PFCP node(s) reachable. Recommendation: N4 must be isolated '
                'from any untrusted network and protected (IPsec/private VLAN); '
                'a reachable UPF/SMF control plane enables session hijack and DoS.'
                % len(found), TAG=TAG)
        _write_results(output_file, found)
    else:
        logInfo('No PFCP nodes responded on the target(s).', TAG=TAG)
    return found
