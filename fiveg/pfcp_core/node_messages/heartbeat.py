#!/usr/bin/env python3
'''
PFCP Heartbeat Request / Response (TS 29.244 clause 7.4.2).

A Heartbeat Request carries a Recovery Time Stamp and is the cheapest way to
probe whether a host is a live PFCP node (UPF/SMF) on N4.
'''
from fiveg.pfcp_core.commons import pfcp_commons as C
from fiveg.pfcp_core.commons.pfcp_msg_base import PfcpMessageBase
from fiveg.pfcp_core.commons.pfcp_ie import RecoveryTimeStamp


class HeartbeatRequest(PfcpMessageBase):

    def __init__(self, sequence=1, recovery_ts=None):
        PfcpMessageBase.__init__(
            self, C.PFCPmessageTypeDigit['heartbeat-request'], sequence=sequence)
        self.add_ie(RecoveryTimeStamp(recovery_ts))


class HeartbeatResponse(PfcpMessageBase):

    def __init__(self, sequence=1, recovery_ts=None):
        PfcpMessageBase.__init__(
            self, C.PFCPmessageTypeDigit['heartbeat-response'], sequence=sequence)
        self.add_ie(RecoveryTimeStamp(recovery_ts))
