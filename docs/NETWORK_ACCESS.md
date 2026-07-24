# Getting Legitimate Network Access

SigPloit's attacks talk to real signaling protocols (SS7, GTP, Diameter,
SIP, PFCP, 5G SBI). To use it against anything beyond
[the virtual lab](PREREQUISITES.md#5-optional-the-virtual-lab-no-live-telecom-access-required)
or your own core network, you need **authorized access to a real
interconnect or operator network** — and that access is a contractual and
procedural matter, not a technical one. This guide explains who to go
through and what the process typically looks like.

This is general orientation, not legal advice — engagement terms vary by
operator, country, and regulator. Read it alongside
[Responsible use](USAGE.md#responsible-use).

## Table of contents

- [The three legitimate paths](#the-three-legitimate-paths)
- [Path 1: contract directly with the operator (pentest engagement)](#path-1-contract-directly-with-the-operator-pentest-engagement)
- [Path 2: go through a GRX/IPX interconnect carrier](#path-2-go-through-a-grxipx-interconnect-carrier)
- [Path 3: become an MVNO or roaming partner](#path-3-become-an-mvno-or-roaming-partner)
- [5G: the same model, over N32/SEPP](#5g-the-same-model-over-n32sepp)
- [Vendor and industry test environments](#vendor-and-industry-test-environments)
- [GSMA's role](#gsmas-role)
- [Practical checklist](#practical-checklist)
- [If in doubt](#if-in-doubt)

---

## The three legitimate paths

| Path | What you get | Typical requester |
|---|---|---|
| [Direct pentest engagement](#path-1-contract-directly-with-the-operator-pentest-engagement) with the MNO | Scoped, time-boxed access to that operator's own signaling elements (HLR/HSS/MME/SGSN/S-CSCF/UPF/...) | Security consultancies, in-house red teams |
| [GRX/IPX carrier](#path-2-go-through-a-grxipx-interconnect-carrier) sponsorship | Access to the shared roaming/interconnect fabric that carries SS7, Diameter, GTP, and now 5G N32 traffic between operators | Operators, carriers, and their contracted testers |
| [MVNO or roaming partner](#path-3-become-an-mvno-or-roaming-partner) status | A real subscriber base and real interconnect signaling to test against, as a side effect of operating a service | Companies running an actual mobile service |

There is no path that grants access without an operator, carrier, or
regulator knowing who you are and agreeing to the test — that's by design,
and it's also what protects you legally: without it, the attacks in this
tool are unauthorized use of a telecommunications network / computer misuse
in essentially every jurisdiction.

---

## Path 1: contract directly with the operator (pentest engagement)

The most common route for security testing: the Mobile Network Operator
(MNO) itself commissions the test.

1. **Engage the operator's security team** (often called Group Security,
   Fraud & Security, or the SOC/CSIRT) — directly, or through their
   procurement process if you're an external consultancy.
2. **Scope and sign a Statement of Work / engagement contract** covering:
   - the exact network elements and interfaces in scope (e.g. "S6a between
     the test MME and production HSS", "SS7 GT range 12345xxxxx", "the lab
     PFCP UPF at 10.x.x.x");
   - the time window and rate limits (DoS-class attacks — GTP DoS, Diameter
     CLR/PUR, SIP INVITE flood, PFCP session DoS — need explicit,
     narrow authorization, since they can affect live subscribers);
   - a named point of contact on the operator's side reachable during the
     test, for an immediate stop if something unexpected happens;
   - reporting and disclosure terms (this is also where SigPloit's
     per-attack **recommendations** feed directly into the deliverable).
3. **Get provisioned**: the operator issues you Global Titles / SS7 point
   codes, an SCTP/Diameter peer relationship (Origin-Host, Origin-Realm,
   IP), a SIP trunk, or PFCP/N4 reachability into a **test** or
   **pre-production** element — real operators virtually never open live
   production core signaling to an external tester directly; you test
   against their lab/pre-prod replica, which mirrors production
   configuration.
4. **Notify their upstream carriers if required** — if the scope includes
   anything reachable from the roaming interconnect (not just an isolated
   lab), the operator typically needs to notify their GRX/IPX carrier(s)
   and, for anything that could be visible to other operators, may need to
   coordinate through GSMA (see [GSMA's role](#gsmas-role)).

This is the path used by the telecom security consultancies referenced in
SigPloit's own background (e.g. the GSMA FS.07 document SigPloit is
referenced in came out of exactly this kind of engagement work).

---

## Path 2: go through a GRX/IPX interconnect carrier

SS7, Diameter (S6a/S6d), GTP roaming, and 5G N32 all ride on a shared,
purpose-built interconnect fabric — the **GRX** (GPRS Roaming Exchange) and
**IPX** (IP eXchange) networks — rather than the public internet. These are
run by a small number of global interconnect carriers who provide
operators with roaming and interconnect connectivity as a paid service.
Well-known IPX/GRX providers include:

- **Syniverse**
- **BICS** (Belgacom International Carrier Services)
- **Tata Communications**
- **Deutsche Telekom Global Carrier**
- **Orange International Carriers**
- **Comfone**
- **iBasis**
- **Sinch**

(This list is illustrative and not exhaustive or an endorsement — the IPX
market shifts over time; check GSMA's IPX Directory / current operator
agreements for the up-to-date list of providers your target operator
actually uses.)

**How this becomes network access for testing:** you don't approach an IPX
carrier "cold" for attack access — you get there in one of two ways:

- **As the operator's chosen test conduit**: the operator authorizing your
  test (see [Path 1](#path-1-contract-directly-with-the-operator-pentest-engagement))
  arranges with their own IPX carrier for you to reach the scoped test
  element via the interconnect, exactly like a real roaming partner would.
  This is the realistic route for testing SS7/Diameter/GTP/N32 attacks
  *as they would actually be exploited over the interconnect*, rather than
  only against an isolated lab element.
- **As a carrier's own customer**: if you (or your employer) operate as a
  carrier, MVNO, or signaling service provider, you can contract directly
  with an IPX/GRX provider for interconnect access, and then use that
  standing relationship — with the counterpart operator's separate,
  explicit authorization — to run scoped tests.

Either way, the IPX carrier requires a signed interconnect/roaming
agreement, technical provisioning (Global Title ranges, Diameter realm
routing, SCTP/IPsec peering, N32-c/N32-f for 5G), and — for anything
touching a specific operator's subscribers — that operator's own sign-off.

---

## Path 3: become an MVNO or roaming partner

If your organization runs an actual mobile service — as a full MNO, an
MVNO (Mobile Virtual Network Operator), or an MVNE (Mobile Virtual Network
Enabler) — you gain legitimate interconnect and roaming relationships as
part of normal operations: your own HLR/HSS talks Diameter/SS7 to roaming
partners' networks, your own SGW/UPF exchanges GTP/PFCP with visited
networks, and so on. Security testing of *your own* elements and *your own*
roaming links (with the roaming partner's consent, since roaming is
bilateral) is then a natural extension of your operational security
program rather than a separate access-acquisition exercise.

This path has a much higher bar to entry (spectrum/MVNO agreements,
national telecom regulator licensing, capital investment) and is
realistically only relevant if network operation — not just security
testing — is already the business you're in.

---

## 5G: the same model, over N32/SEPP

5G doesn't change who you go through — it changes the interconnect
protocol. Operators now peer at the edge via the **SEPP** (Security Edge
Protection Proxy) over the **N32** reference point, and the same IPX/GRX
carriers listed above have extended their interconnect products to proxy
N32 traffic between operators' SEPPs (often marketed as "5G IPX" or "N32
proxy" services). The access process is the same as
[Path 1](#path-1-contract-directly-with-the-operator-pentest-engagement) /
[Path 2](#path-2-go-through-a-grxipx-interconnect-carrier): get the
operator's authorization, get provisioned by their IPX carrier for N32/SBI
reachability into a scoped test SEPP/NRF/AMF/SMF, and test within that
scope. SigPloit's 5G attacks (NRF discovery, NF access, PFCP) are written
against exactly that kind of scoped SBI/N4 reachability.

---

## Vendor and industry test environments

A few organizations offer signaling test/sandbox environments that sit
between "your own lab" and "a live operator engagement," useful if you want
realistic interconnect behavior without a full operator contract:

- **Telecom security vendors** (e.g. Enea AdaptiveMobile Security, Mobileum,
  P1 Security, SecurityGen) run signaling testing and monitoring platforms
  and, in some cases, offer sandboxed or simulated interconnect environments
  as part of their consulting/training engagements.
- **Equipment/protocol vendors'** own interoperability labs sometimes admit
  external testers under contract for pre-deployment security assessment of
  a specific product.
- **GSMA's Test & Certification / interoperability test events** provide
  structured environments for testing against multiple vendors'
  implementations, primarily aimed at conformance rather than offensive
  security testing, but sometimes usable as a realistic multi-vendor
  signaling environment under the relevant program's terms.

Availability, cost, and scope for these vary; contact the vendor/program
directly for current terms.

---

## GSMA's role

The **GSMA** (GSM Association) is the industry body that coordinates
signaling security across operators, and is worth engaging with directly
once your test scope extends beyond a single operator's isolated lab:

- **GSMA FS.07** "SS7 and Sigtran Network Security" — the document SigPloit
  itself is referenced in; background on SS7 interconnect threats.
- **GSMA FS.11** "SS7 Interconnect Security Monitoring Guidelines" and the
  related **FS.19/FS.20** Diameter interconnect security guidelines —
  operator-facing hardening guidance that maps directly onto what
  SigPloit's Diameter/SS7 attacks demonstrate.
- **GSMA Coordinated Vulnerability Disclosure (CVD) programme** — the
  right channel if testing (authorized or incidental) surfaces a
  vulnerability that affects operators beyond the one that authorized your
  test, since SS7/Diameter/N32 issues frequently do.
- **GSMA T-ISAC** (Telecommunication Information Sharing and Analysis
  Center) — the operator community's threat-intelligence and coordination
  body; large-scope interconnect tests are often coordinated through or
  disclosed to this body so other operators aren't caught off guard by
  traffic that transits shared infrastructure.

For anything beyond a single operator's isolated lab element, loop in
GSMA (via the sponsoring operator, who is normally already a GSMA member)
rather than assuming a bilateral agreement with one operator is sufficient
authorization for interconnect-wide testing.

---

## Practical checklist

Before you point SigPloit at anything other than
[the local mock targets](USAGE.md#practicing-safely-mock-targets) or
[the bundled SS7 test lab](PREREQUISITES.md#5a-bundled-ss7-test-servers-testing):

- [ ] Signed engagement contract / SOW naming the specific operator,
      network elements, and interfaces in scope.
- [ ] Written confirmation of the exact target addressing (Global
      Titles/point codes, Diameter Origin-Host/Realm and peer IPs, SIP
      domain, PFCP/N4 or SBI endpoints) — never assume scope, get it in
      writing.
- [ ] Agreed time window and named emergency point of contact on the
      operator's side.
- [ ] Explicit, separate sign-off for any DoS-class attack (GTP DoS,
      Diameter CLR/PUR, SIP INVITE flood, PFCP session DoS) — these can
      affect live subscribers and are usually the most tightly scoped part
      of an engagement.
- [ ] Confirmation of whether the test traffic could transit shared
      interconnect (GRX/IPX) and, if so, that the relevant carrier and/or
      GSMA coordination has happened.
- [ ] A defined reporting process — SigPloit's per-attack recommendation
      output is meant to feed straight into this.

## If in doubt

If you're not sure whether you have the access needed for a given target —
you don't. Stop and get it in writing before running anything beyond the
[virtual lab](PREREQUISITES.md#5-optional-the-virtual-lab-no-live-telecom-access-required).
See [Responsible use](USAGE.md#responsible-use) for the legal framing.
