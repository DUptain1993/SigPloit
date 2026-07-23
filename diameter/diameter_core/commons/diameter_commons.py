#!/usr/bin/env python3
'''
Diameter constants (RFC 6733 base protocol + 3GPP S6a/S6d, TS 29.272).

Diameter is the signaling protocol of the LTE/EPC roaming interconnect.  The S6a
interface runs between the MME and the HSS and carries subscriber
authentication, location update and subscriber-data management.
'''

# Default Diameter transport port (RFC 6733). Diameter may run over TCP or SCTP.
DIAMETER_TCP_PORT = 3868

DIAMETER_VERSION = 1

# --- Application IDs ---------------------------------------------------------
APP_COMMON = 0                 # base / CER / DWR / DPR
APP_S6A = 16777251             # 3GPP S6a/S6d
VENDOR_3GPP = 10415

# --- Command codes (RFC 6733 + TS 29.272) -----------------------------------
CMD_CER = 257                  # Capabilities-Exchange
CMD_DWR = 280                  # Device-Watchdog
CMD_DPR = 282                  # Disconnect-Peer
CMD_ULR = 316                  # Update-Location  (S6a)
CMD_CLR = 317                  # Cancel-Location  (S6a)
CMD_AIR = 318                  # Authentication-Information (S6a)
CMD_IDR = 319                  # Insert-Subscriber-Data (S6a)
CMD_DSR = 320                  # Delete-Subscriber-Data (S6a)
CMD_PUR = 321                  # Purge-UE (S6a)
CMD_NOR = 323                  # Notify (S6a)

CMD_NAME = {
    257: 'Capabilities-Exchange', 280: 'Device-Watchdog',
    282: 'Disconnect-Peer', 316: 'Update-Location', 317: 'Cancel-Location',
    318: 'Authentication-Information', 319: 'Insert-Subscriber-Data',
    320: 'Delete-Subscriber-Data', 321: 'Purge-UE', 323: 'Notify',
}

# --- Command flag bits (in the command-flags octet) -------------------------
FLAG_REQUEST = 0x80
FLAG_PROXIABLE = 0x40
FLAG_ERROR = 0x20

# --- AVP codes (base, RFC 6733) ---------------------------------------------
AVP_USER_NAME = 1
AVP_HOST_IP_ADDRESS = 257
AVP_AUTH_APPLICATION_ID = 258
AVP_VENDOR_SPECIFIC_APPLICATION_ID = 260
AVP_SESSION_ID = 263
AVP_ORIGIN_HOST = 264
AVP_SUPPORTED_VENDOR_ID = 265
AVP_VENDOR_ID = 266
AVP_FIRMWARE_REVISION = 267
AVP_RESULT_CODE = 268
AVP_PRODUCT_NAME = 269
AVP_ORIGIN_STATE_ID = 278
AVP_AUTH_SESSION_STATE = 277
AVP_DESTINATION_REALM = 283
AVP_DESTINATION_HOST = 293
AVP_ORIGIN_REALM = 296
AVP_INBAND_SECURITY_ID = 299

# --- AVP codes (3GPP S6a, vendor 10415, TS 29.272 / 29.229) -----------------
AVP_VISITED_PLMN_ID = 1407
AVP_RAT_TYPE = 1032
AVP_ULR_FLAGS = 1405
AVP_ULA_FLAGS = 1406
AVP_REQ_EUTRAN_AUTH_INFO = 1408
AVP_NUM_REQUESTED_VECTORS = 1410
AVP_IMMEDIATE_RESPONSE_PREFERRED = 1412
AVP_CANCELLATION_TYPE = 1420
AVP_PUR_FLAGS = 1635

# --- Auth-Session-State values ----------------------------------------------
NO_STATE_MAINTAINED = 1

# --- Result codes -----------------------------------------------------------
DIAMETER_SUCCESS = 2001
RESULT_CODE_NAME = {
    2001: 'DIAMETER_SUCCESS',
    3002: 'DIAMETER_UNABLE_TO_DELIVER',
    3007: 'DIAMETER_APPLICATION_UNSUPPORTED',
    5001: 'DIAMETER_AVP_UNSUPPORTED',
    5003: 'DIAMETER_AUTHORIZATION_REJECTED',
    5012: 'DIAMETER_UNABLE_TO_COMPLY',
    5420: 'DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION',
    5421: 'DIAMETER_ERROR_RAT_NOT_ALLOWED',
}

# Cancellation-Type values (TS 29.272 clause 7.3.24)
CANCELLATION_MME_UPDATE = 0
CANCELLATION_SUBSCRIPTION_WITHDRAWAL = 2
