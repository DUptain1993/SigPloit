#!/usr/bin/env python3
'''
PFCP (Packet Forwarding Control Protocol) constants.

PFCP is the N4 reference-point protocol between the SMF (control plane) and the
UPF (user plane) in the 5G core, runs over UDP port 8805, and is specified in
3GPP TS 29.244.  The message-type and IE-type tables below follow TS 29.244
release 16.
'''

# UDP port for PFCP (TS 29.244 clause 4.2.2)
PFCP_UDP_PORT = 8805

# PFCP protocol version carried in the top three bits of octet 1.
PFCP_VERSION = 1

# NTP epoch offset (seconds between 1900-01-01 and 1970-01-01), used for the
# Recovery Time Stamp IE.
NTP_EPOCH_OFFSET = 2208988800


# --- Message types (TS 29.244 Table 7.3-1) ---------------------------------
PFCPmessageTypeDigit = {
    'heartbeat-request': 1,
    'heartbeat-response': 2,
    'pfd-management-request': 3,
    'pfd-management-response': 4,
    'association-setup-request': 5,
    'association-setup-response': 6,
    'association-update-request': 7,
    'association-update-response': 8,
    'association-release-request': 9,
    'association-release-response': 10,
    'version-not-supported-response': 11,
    'node-report-request': 12,
    'node-report-response': 13,
    'session-set-deletion-request': 14,
    'session-set-deletion-response': 15,
    'session-establishment-request': 50,
    'session-establishment-response': 51,
    'session-modification-request': 52,
    'session-modification-response': 53,
    'session-deletion-request': 54,
    'session-deletion-response': 55,
    'session-report-request': 56,
    'session-report-response': 57,
}

PFCPmessageTypeStr = {v: k for k, v in PFCPmessageTypeDigit.items()}

# Session-related messages carry a SEID in the header (S flag = 1).
SESSION_MESSAGE_TYPES = set(range(50, 58))


# --- Information Element types (TS 29.244 Table 8.1.2-1) --------------------
PFCP_IE = {
    'create-pdr': 1,
    'pdi': 2,
    'create-far': 3,
    'forwarding-parameters': 4,
    'cause': 19,
    'source-interface': 20,
    'f-teid': 21,
    'network-instance': 22,
    'precedence': 29,
    'apply-action': 44,
    'pdr-id': 56,
    'f-seid': 57,
    'node-id': 60,
    'far-id': 108,
    'ue-ip-address': 93,
    'recovery-time-stamp': 96,
    'up-function-features': 43,
    'cp-function-features': 89,
}


# --- Cause values (TS 29.244 Table 8.2.1-1) --------------------------------
PFCP_CAUSE = {
    'request-accepted': 1,
    'request-rejected': 64,
    'session-context-not-found': 65,
    'mandatory-ie-missing': 66,
    'conditional-ie-missing': 67,
    'invalid-length': 68,
    'mandatory-ie-incorrect': 69,
    'invalid-forwarding-policy': 70,
    'system-failure': 72,
    'no-resources-available': 73,
    'service-not-supported': 74,
}

PFCP_CAUSE_STR = {v: k for k, v in PFCP_CAUSE.items()}

# Node ID types (TS 29.244 clause 8.2.38)
NODE_ID_IPV4 = 0
NODE_ID_IPV6 = 1
NODE_ID_FQDN = 2

# Source Interface values (TS 29.244 clause 8.2.2)
SRC_IFACE_ACCESS = 0
SRC_IFACE_CORE = 1
SRC_IFACE_SGI_N6 = 2
SRC_IFACE_CP = 3

# Apply Action bit flags (TS 29.244 clause 8.2.26)
APPLY_ACTION_DROP = 0x01
APPLY_ACTION_FORW = 0x02
APPLY_ACTION_BUFF = 0x04
APPLY_ACTION_NOCP = 0x08
APPLY_ACTION_DUPL = 0x10
