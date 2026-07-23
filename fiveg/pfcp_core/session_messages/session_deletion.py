#!/usr/bin/env python3
'''
PFCP Session Deletion / Modification Requests (TS 29.244 clauses 7.5.4/7.5.6).

Session Deletion tears down an existing N4 session identified by the SEID in the
header.  Sent with a UPF-assigned SEID it removes forwarding state for a
subscriber; that is the primitive behind the N4 session-teardown denial of
service.
'''
from fiveg.pfcp_core.commons import pfcp_commons as C
from fiveg.pfcp_core.commons.pfcp_msg_base import PfcpMessageBase


class SessionDeletionRequest(PfcpMessageBase):

    def __init__(self, seid, sequence=1):
        PfcpMessageBase.__init__(
            self, C.PFCPmessageTypeDigit['session-deletion-request'],
            seid=seid, sequence=sequence)
        # Session Deletion Request has no mandatory IEs; the target session is
        # identified solely by the SEID in the header.


class SessionModificationRequest(PfcpMessageBase):

    def __init__(self, seid, sequence=1, far=None):
        PfcpMessageBase.__init__(
            self, C.PFCPmessageTypeDigit['session-modification-request'],
            seid=seid, sequence=sequence)
        if far is not None:
            self.add_ie(far)
