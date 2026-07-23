#!/usr/bin/env python3
'''
PFCP Association Setup Request / Response (TS 29.244 clause 7.4.4).

An Association Setup Request from a (real or spoofed) SMF is what establishes the
N4 control relationship with a UPF.  It carries the sender Node ID and a Recovery
Time Stamp; a UPF that answers with cause "request accepted" has accepted the
association.
'''
from fiveg.pfcp_core.commons import pfcp_commons as C
from fiveg.pfcp_core.commons.pfcp_msg_base import PfcpMessageBase
from fiveg.pfcp_core.commons.pfcp_ie import NodeID, RecoveryTimeStamp, Cause


class AssociationSetupRequest(PfcpMessageBase):

    def __init__(self, node_id='127.0.0.1', node_type=C.NODE_ID_IPV4,
                 sequence=1, recovery_ts=None):
        PfcpMessageBase.__init__(
            self, C.PFCPmessageTypeDigit['association-setup-request'],
            sequence=sequence)
        self.add_ie(NodeID(node_id, node_type))
        self.add_ie(RecoveryTimeStamp(recovery_ts))


class AssociationSetupResponse(PfcpMessageBase):

    def __init__(self, node_id='127.0.0.1', node_type=C.NODE_ID_IPV4,
                 cause=C.PFCP_CAUSE['request-accepted'], sequence=1,
                 recovery_ts=None):
        PfcpMessageBase.__init__(
            self, C.PFCPmessageTypeDigit['association-setup-response'],
            sequence=sequence)
        self.add_ie(NodeID(node_id, node_type))
        self.add_ie(Cause(cause))
        self.add_ie(RecoveryTimeStamp(recovery_ts))
