#!/usr/bin/env python3
'''
Shared helpers for the Diameter S6a attacks: open a connection, run the CER/CEA
handshake, send one S6a request and decode the answer's result code.
'''
import struct

from IPy import IP

from diameter.diameter_core.commons import diameter_commons as C
from diameter.diameter_core.commons import avp as A
from diameter.diameter_core.diameter_transport import DiameterConnection
from diameter.commons.utilities import logOk, logErr, logWarn, logInfo, logNormal


def targets(remote_net):
    try:
        return [ip.strNormal() for ip in IP(remote_net)]
    except (ValueError, TypeError):
        return [remote_net]


def result_code(avps):
    '''Return (code:int, name:str) from a Result-Code / Experimental-Result AVP.'''
    rc = A.find_avp(avps, C.AVP_RESULT_CODE)
    if rc and len(rc['value']) >= 4:
        code = struct.unpack('!I', rc['value'][:4])[0]
        return code, C.RESULT_CODE_NAME.get(code, str(code))
    exp = A.find_avp(avps, 297)  # Experimental-Result (grouped)
    if exp:
        sub = A.parse_avps(exp['value'])
        erc = A.find_avp(sub, 298)
        if erc and len(erc['value']) >= 4:
            code = struct.unpack('!I', erc['value'][:4])[0]
            return code, C.RESULT_CODE_NAME.get(code, str(code))
    return None, None


def open_s6a(cfg, host, tag):
    '''Connect + CER handshake. Returns a connected DiameterConnection or None.'''
    conn = DiameterConnection(host, cfg.port, origin_host=cfg.origin_host,
                              origin_realm=cfg.origin_realm, host_ip=cfg.host_ip,
                              use_sctp=cfg.use_sctp, timeout=cfg.timeout)
    try:
        conn.connect()
    except OSError as e:
        logNormal('%s: connect failed (%s)' % (host, e), verbose=True, TAG=tag)
        return None
    cea = conn.capabilities_exchange()
    if cea is None:
        logNormal('%s: no CEA (not a Diameter peer?)' % host, verbose=True, TAG=tag)
        conn.close()
        return None
    header, _ = cea
    logInfo('%s: CER/CEA ok (%s, app=%d)'
            % (host, header['command_name'], header['application_id']), TAG=tag)
    return conn


def send_and_report(conn, host, message, tag, success_msg, recommendation):
    '''Send one S6a request, decode + report the answer's result code.'''
    result = conn.request(message)
    if result is None:
        logWarn('%s: no answer to %s' % (host, C.CMD_NAME.get(message.command_code, '?')),
                TAG=tag)
        return None
    header, avps, _ = result
    code, name = result_code(avps)
    if code == C.DIAMETER_SUCCESS:
        logOk('%s: %s ANSWER = %s (%s) - %s'
              % (host, header['command_name'], code, name, success_msg), TAG=tag)
        logWarn('Recommendation: %s' % recommendation, TAG=tag)
    elif code is not None:
        logInfo('%s: %s ANSWER = %s (%s)'
                % (host, header['command_name'], code, name), TAG=tag)
    else:
        logInfo('%s: %s ANSWER received (no result code parsed)'
                % (host, header['command_name']), TAG=tag)
    return code
