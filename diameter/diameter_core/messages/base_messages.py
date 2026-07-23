#!/usr/bin/env python3
'''
Diameter base-protocol messages: CER (Capabilities-Exchange-Request) and
DWR (Device-Watchdog-Request), RFC 6733.

CER is exchanged right after the transport connection opens; a peer that answers
with a CEA is a live Diameter node, which makes CER the basis of peer discovery.
'''
import time

from diameter.diameter_core.commons import diameter_commons as C
from diameter.diameter_core.commons import avp as A
from diameter.diameter_core.commons.diameter_msg_base import DiameterMessage


def capabilities_exchange_request(origin_host, origin_realm, host_ip,
                                  product_name='SigPloit',
                                  advertise_s6a=True):
    msg = DiameterMessage(C.CMD_CER, application_id=C.APP_COMMON, request=True)
    msg.add(A.utf8(C.AVP_ORIGIN_HOST, origin_host))
    msg.add(A.utf8(C.AVP_ORIGIN_REALM, origin_realm))
    msg.add(A.address(C.AVP_HOST_IP_ADDRESS, host_ip))
    msg.add(A.unsigned32(C.AVP_VENDOR_ID, C.VENDOR_3GPP))
    msg.add(A.utf8(C.AVP_PRODUCT_NAME, product_name, mandatory=False))
    msg.add(A.unsigned32(C.AVP_ORIGIN_STATE_ID, int(time.time())))
    if advertise_s6a:
        msg.add(A.unsigned32(C.AVP_SUPPORTED_VENDOR_ID, C.VENDOR_3GPP))
        msg.add(A.grouped(C.AVP_VENDOR_SPECIFIC_APPLICATION_ID, [
            A.unsigned32(C.AVP_VENDOR_ID, C.VENDOR_3GPP),
            A.unsigned32(C.AVP_AUTH_APPLICATION_ID, C.APP_S6A),
        ]))
    else:
        msg.add(A.unsigned32(C.AVP_AUTH_APPLICATION_ID, C.APP_COMMON))
    return msg


def device_watchdog_request(origin_host, origin_realm):
    msg = DiameterMessage(C.CMD_DWR, application_id=C.APP_COMMON, request=True)
    msg.add(A.utf8(C.AVP_ORIGIN_HOST, origin_host))
    msg.add(A.utf8(C.AVP_ORIGIN_REALM, origin_realm))
    msg.add(A.unsigned32(C.AVP_ORIGIN_STATE_ID, int(time.time())))
    return msg
