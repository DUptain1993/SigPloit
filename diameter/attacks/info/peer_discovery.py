#!/usr/bin/env python3
'''
Diameter Peer Discovery.

Sweeps a target host or subnet by opening a Diameter connection and performing
the CER/CEA capabilities handshake.  A peer that answers CEA is a live Diameter
node (HSS/MME/DRA); the CEA's advertised Vendor-Specific-Application-Id tells us
whether it speaks S6a.

    main(config_file, remote_net, listening, verbosity, output_file)
'''
import csv

from diameter.diameter_core.diameter_config_parser import DiameterConfig
from diameter.diameter_core.commons import diameter_commons as C
from diameter.diameter_core.commons import avp as A
from diameter.attacks.runner import targets, open_s6a
from diameter.commons.utilities import logOk, logErr, logWarn, logInfo, logNormal

TAG = 'DIAMETER-DISCOVERY'


def _write_results(output_file, rows):
    if not output_file or not rows:
        return
    try:
        with open(output_file, 'w', newline='') as fh:
            writer = csv.writer(fh)
            writer.writerow(['host', 'port', 'origin_host', 'origin_realm', 's6a'])
            writer.writerows(rows)
        logOk('Results written to %s' % output_file, TAG=TAG)
    except OSError as e:
        logErr('Could not write results file: %s' % e, TAG=TAG)


def main(config_file, remote_net, listening=True, verbosity=2,
         output_file='diameter_peers.csv'):
    if not remote_net:
        logErr('No target set. Use "set target <ip|cidr>".', TAG=TAG)
        return

    try:
        cfg = DiameterConfig(config_file)
    except Exception as e:
        logWarn('Config not loaded (%s); using defaults.' % e, TAG=TAG)
        cfg = DiameterConfig()

    verbose = verbosity >= 2
    hosts = targets(remote_net)
    logInfo('Probing %d target(s) on Diameter TCP %d ...' % (len(hosts), cfg.port),
            TAG=TAG)

    found = []
    for host in hosts:
        conn = open_s6a(cfg, host, TAG)
        if conn is None:
            logNormal('%s: no Diameter response' % host, verbose=verbose, TAG=TAG)
            continue
        # re-run CER to inspect the CEA content for reporting
        cea = conn.capabilities_exchange()
        conn.close()
        if cea is None:
            continue
        header, avps = cea
        oh = A.find_avp(avps, C.AVP_ORIGIN_HOST)
        orlm = A.find_avp(avps, C.AVP_ORIGIN_REALM)
        origin_host = oh['value'].decode('utf-8', 'replace') if oh else ''
        origin_realm = orlm['value'].decode('utf-8', 'replace') if orlm else ''
        s6a = False
        for a in avps:
            if a['code'] == C.AVP_VENDOR_SPECIFIC_APPLICATION_ID:
                sub = A.parse_avps(a['value'])
                app = A.find_avp(sub, C.AVP_AUTH_APPLICATION_ID)
                if app and len(app['value']) >= 4:
                    import struct
                    if struct.unpack('!I', app['value'][:4])[0] == C.APP_S6A:
                        s6a = True
        logOk('%s is a live Diameter node  origin_host=%s realm=%s s6a=%s'
              % (host, origin_host or '-', origin_realm or '-', s6a), TAG=TAG)
        found.append([host, cfg.port, origin_host, origin_realm, s6a])

    if found:
        logWarn('%d Diameter peer(s) reachable. Recommendation: restrict the '
                'Diameter/S6a interconnect to authorized MME/HSS peers only '
                '(DRA/DEA filtering, TLS/IPsec, topology hiding).' % len(found),
                TAG=TAG)
        _write_results(output_file, found)
    else:
        logInfo('No Diameter peers responded on the target(s).', TAG=TAG)
    return found
