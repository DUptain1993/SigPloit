#!/usr/bin/env python3
'''
SIP REGISTER Subscriber Enumeration (IMS/VoLTE access layer).

Sends REGISTER for a range of extensions/IMPUs against the target registrar. A
401/407 (auth challenge) means the identity is known/provisioned; a 404 (Not
Found) means it isn't - the classic SIP user-enumeration oracle.

    main(config_file, target, listening, verbosity, output_file)
'''
import csv

from sip.sip_core.sip_config_parser import SipConfig
from sip.sip_core.sip_message import build_request
from sip.sip_core.sip_transport import probe
from sip.commons.utilities import logOk, logErr, logWarn, logInfo, logNormal

TAG = 'SIP-REGISTER-ENUM'

# Status codes that indicate the identity exists (server challenged instead of
# rejecting outright).
EXISTS_CODES = (401, 407, 200)


def _write_results(output_file, rows):
    if not output_file or not rows:
        return
    try:
        with open(output_file, 'w', newline='') as fh:
            writer = csv.writer(fh)
            writer.writerow(['extension', 'status', 'reason', 'exists'])
            writer.writerows(rows)
        logOk('Results written to %s' % output_file, TAG=TAG)
    except OSError as e:
        logErr('Could not write results file: %s' % e, TAG=TAG)


def main(config_file, target, listening=True, verbosity=2,
         output_file='sip_subscribers.csv'):
    if not target:
        logErr('No target set. Use "set target <registrar-ip>".', TAG=TAG)
        return
    try:
        cfg = SipConfig(config_file)
    except Exception as e:
        logErr('Bad config: %s' % e, TAG=TAG)
        return

    verbose = verbosity >= 2
    logInfo('Enumerating extensions %d-%d against %s:%d ...'
            % (cfg.ext_start, cfg.ext_end, target, cfg.port), TAG=TAG)

    found = []
    for ext in range(cfg.ext_start, cfg.ext_end + 1):
        aor = 'sip:%s@%s' % (ext, cfg.domain)
        req = build_request('REGISTER', aor, aor, aor, cfg.local_host,
                            local_port=cfg.local_port or 5060,
                            contact='sip:%s@%s:%d' % (ext, cfg.local_host,
                                                       cfg.local_port or 5060),
                            extra_headers=[('Expires', '0')])
        resp = probe(target, cfg.port, req, timeout=cfg.timeout)
        if resp is not None:
            exists = resp['status_code'] in EXISTS_CODES
            logNormal('%s -> %d %s%s' % (ext, resp['status_code'], resp['reason'],
                      '  [EXISTS]' if exists else ''), verbose=verbose, TAG=TAG)
            if exists:
                logOk('%s is a provisioned subscriber (%d %s)'
                      % (ext, resp['status_code'], resp['reason']), TAG=TAG)
            found.append([ext, resp['status_code'], resp['reason'], exists])
        else:
            logNormal('%s no response' % ext, verbose=verbose, TAG=TAG)

    existing = [r for r in found if r[3]]
    if existing:
        logWarn('%d subscriber identity(ies) disclosed via REGISTER oracle. '
                'Recommendation: return uniform responses (or rate-limit) for '
                'unknown vs. known AORs to prevent subscriber enumeration.'
                % len(existing), TAG=TAG)
    _write_results(output_file, found)
    return found
