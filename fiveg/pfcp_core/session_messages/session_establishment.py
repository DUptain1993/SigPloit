#!/usr/bin/env python3
'''
PFCP Session Establishment Request (TS 29.244 clause 7.5.2).

Creates an N4/PFCP session on the UPF.  Mandatory content is the CP Node ID, the
CP F-SEID and at least one Create PDR + Create FAR.  The header SEID is 0 on the
request (the UPF returns its own F-SEID in the response).
'''
from fiveg.pfcp_core.commons import pfcp_commons as C
from fiveg.pfcp_core.commons.pfcp_msg_base import PfcpMessageBase
from fiveg.pfcp_core.commons.pfcp_ie import NodeID, FSEID, create_pdr, create_far


class SessionEstablishmentRequest(PfcpMessageBase):

    def __init__(self, cp_node_id='127.0.0.1', cp_seid=1, cp_ipv4='127.0.0.1',
                 ue_ipv4=None, sequence=1, node_type=C.NODE_ID_IPV4):
        PfcpMessageBase.__init__(
            self, C.PFCPmessageTypeDigit['session-establishment-request'],
            seid=0, sequence=sequence)
        self.add_ie(NodeID(cp_node_id, node_type))
        self.add_ie(FSEID(cp_seid, ipv4=cp_ipv4))
        self.add_ie(create_pdr(pdr_id=1, source_interface=C.SRC_IFACE_ACCESS,
                               ue_ipv4=ue_ipv4))
        self.add_ie(create_far(far_id=1, action=C.APPLY_ACTION_FORW))
