# Usage Guide

This guide walks through launching SigPloit, how its interactive CLI works,
and a full walkthrough of every attack in every module (SS7, GTP, Diameter,
SIP, 5G) — including the exact menu choices, `.cnf` config fields, and
example commands.

Make sure you've completed [`PREREQUISITES.md`](PREREQUISITES.md) first.

## Table of contents

- [Responsible use](#responsible-use)
- [Launching SigPloit](#launching-sigploit)
- [The interactive CLI model](#the-interactive-cli-model)
- [Full menu map](#full-menu-map)
- [SS7 module](#ss7-module)
- [GTP module](#gtp-module)
- [Diameter module](#diameter-module)
- [SIP module](#sip-module)
- [5G module](#5g-module)
- [Config file format reference](#config-file-format-reference)
- [Output files](#output-files)
- [Practicing safely: mock targets](#practicing-safely-mock-targets)
- [Troubleshooting](#troubleshooting)

---

## Responsible use

Every attack in this framework sends real, standards-compliant signaling
messages (SS7 MAP, GTP-C, Diameter S6a, SIP, PFCP, 5G SBI). Run them only
against:

- A network/lab you own or control (see
  [the virtual lab section](PREREQUISITES.md#5-optional-the-virtual-lab-no-live-telecom-access-required)), or
- A production or partner network you have **explicit, written authorization**
  to test (e.g. a signed penetration-testing engagement).

Several attacks are denial-of-service by design (GTP DoS, Diameter
Cancel-Location/Purge-UE, SIP INVITE flood, PFCP session DoS) — running them
against a network without authorization can disrupt real subscriber service
and is illegal in most jurisdictions. Each attack prints a **recommendation**
on completion describing how to remediate the exposure it just demonstrated;
that recommendation is the deliverable for a legitimate engagement.

---

## Launching SigPloit

From the repository root:

```bash
python3 sigploit.py
```

This prints the ASCII banner and the top-level module menu:

```
   Module               Description
   --------                --------------------
0) SS7                  2G/3G Voice and SMS attacks
1) GTP                  3G/4G Data attacks
2) Diameter             4G Data attacks
3) SIP                  4G IMS attacks
4) 5G                   5G Core (SBA/HTTP2 & PFCP/N4) attacks

or quit to exit SigPloit

sig>
```

Type a digit to enter that module, or `quit`/`exit` (or Ctrl-C) at any time
to leave SigPloit. Every submenu accepts `back` to return one level up.

---

## The interactive CLI model

SigPloit has **two different interaction styles**, depending on the module:

### 1. SS7 — direct launch + y/n prompts

SS7 attacks are compiled Java payloads (jSS7-based). Selecting one launches
the `.jar` immediately (it has its own configuration, typically hardcoded or
prompted for by the Java program itself). After it finishes, SigPloit asks a
simple yes/no chain to decide where to go next:

```
Would you like to go back to LocationTracking Menu? (y/n):
Would you like to choose another attacks category? (y/n):
Would you like to go back to the main menu? (y/exit):
```

### 2. GTP / Diameter / SIP / 5G — Metasploit-style attack shells

Every attack in the Python-native modules (GTP, Diameter, SIP, 5G) drops you
into a small interactive shell with a consistent command set:

| Command | Effect |
|---|---|
| `show options` | Print the current value of every option (`config`, `target`, `listening`, `verbosity`, `output`, plus any attack-specific option like `mode`). |
| `set <option> <value>` | Set an option, e.g. `set target 10.0.0.5` or `set config diameter/config/AuthInfo.cnf`. |
| `run` | Execute the attack with the current options. |
| `help` (or `?`) | Show the command list. |
| `back` | Return to the parent menu. |
| `exit` | Quit SigPloit entirely from inside the shell. |

The common options across all four modules:

| Option | Meaning |
|---|---|
| `config` | Path to the attack's `.cnf` file (identity, peer, subscriber parameters — see [config reference](#config-file-format-reference)). |
| `target` | The IP, hostname, or CIDR (e.g. `10.0.0.0/24`) of the peer/network element to attack. Discovery/sweep attacks accept a CIDR; single-peer attacks (AIR, ULR, INVITE spoof, ...) expect one host. |
| `listening` | Whether to wait for/process replies (`true`/`false`). |
| `verbosity` | `0`-`2`; `2` prints every message sent/received, lower values only print results. |
| `output` | Path to a `.csv` results file (discovery/enumeration attacks write their findings here). |

A typical session looks like:

```
(peer-discover)> set config diameter/config/PeerDiscovery.cnf
(peer-discover)> set target 10.0.0.5
(peer-discover)> show options
(peer-discover)> run
(peer-discover)> back
```

Some DoS attacks add an extra `mode` option (documented per-attack below),
e.g. `set mode purge`.

---

## Full menu map

```
sigploit.py (main menu)
├─ 0) SS7                     -> ss7main.attacksMenu()
│  ├─ 0) Location Tracking     -> SendRoutingInfo / ProvideSubscriberInfo /
│  │                             SendRoutingInfoForSM / AnyTimeInterrogation /
│  │                             SendRoutingInfoForGPRS
│  ├─ 1) Call and SMS Interception -> UpdateLocation
│  ├─ 2) Fraud & Info Gathering -> SendIMSI / MTForwardSMS /
│  │                               InsertSubscriberData / SendAuthenticationInfo
│  └─ 3) DoS                    -> PurgeMS
│
├─ 1) GTP                     -> gtpmain.prep() -> [0 GTPv1(pending) | 1 GTPv2]
│  ├─ 0) Information Gathering -> GTP Nodes Discovery / TEID Allocation
│  │                              Discovery / TEID Predictability
│  ├─ 1) Fraud                 -> Tunnel Hijack
│  └─ 2) Denial of Service     -> Massive DoS / User DoS
│
├─ 2) Diameter                -> diametermain.diameterattacks()
│  ├─ 0) Information Gathering -> Peer Discovery
│  ├─ 1) Location Tracking     -> Authentication Info (AIR)
│  ├─ 2) Interception          -> Update Location (ULR)
│  └─ 3) Denial of Service     -> Subscriber DoS (Cancel-Location / Purge-UE)
│
├─ 3) SIP                     -> sipmain.sipattacks()
│  ├─ 0) Information Gathering -> OPTIONS Discovery / REGISTER Enumeration
│  ├─ 1) Interception          -> INVITE Spoofing
│  └─ 2) Denial of Service     -> INVITE Flood
│
└─ 4) 5G                      -> fivegmain.fivegattacks()
   ├─ 0) Information Gathering -> PFCP Node Discovery / NRF NF Discovery
   ├─ 1) Service Based Architecture (SBA) -> NF Unauthorized Access
   └─ 2) Denial of Service     -> PFCP Session DoS (establish|delete)
```

---

## SS7 module

**Menu path:** `0) SS7`. Requires Java (see prerequisites) and either live
SS7 access or the [bundled test servers](PREREQUISITES.md#5a-bundled-ss7-test-servers-testing).

### 0) Location Tracking

| # | Attack | What it does |
|---|---|---|
| 0 | SendRoutingInfo | Retrieve subscriber routing info (can be blocked by call-routing filters). |
| 1 | ProvideSubscriberInfo | Reliable location tracking. |
| 2 | SendRoutingInfoForSM | Reliable location tracking via the SMS path; run it twice to check for consistent replies (a sign SMS Home Routing is not applied). |
| 3 | AnyTimeInterrogation | Location tracking; blocked by most modern operators. |
| 4 | SendRoutingInfoForGPRS | Retrieves the subscriber's serving SGSN, used to route data. |

### 1) Call and SMS Interception

| # | Attack | What it does |
|---|---|---|
| 0 | UpdateLocation | Stealthy SMS interception by re-registering the subscriber's serving MSC/VLR. |

### 2) Fraud & Info Gathering

| # | Attack | What it does |
|---|---|---|
| 0 | SendIMSI | Retrieve a subscriber's IMSI from their MSISDN. |
| 1 | MTForwardSMS | SMS phishing / sender-ID spoofing. |
| 2 | InsertSubscriberData | Manipulate a subscriber's profile in the VLR/HLR. |
| 3 | SendAuthenticationInfo | Retrieve subscriber authentication vectors. |

### 3) DoS

| # | Attack | What it does |
|---|---|---|
| 0 | PurgeMS | Mass DoS — forces subscribers off the network. |

Each SS7 attack launches its bundled `.jar` directly; consult
`ss7/attacks/**/META-INF` and the corresponding
[test-server instructions](PREREQUISITES.md#5a-bundled-ss7-test-servers-testing)
for the exact parameters each jar expects.

---

## GTP module

**Menu path:** `1) GTP` → choose `1) GTPv2` (`0) GTPv1` is not yet
implemented). GTP is the 3G/4G data-roaming protocol (GTP-C, control plane)
used on the IPX/GRX interconnect. All attacks are driven by `.cnf` files in
[`gtp/config/`](../gtp/config).

### 0) Information Gathering

**GTP Nodes Discovery** (`0`) — sweeps `target` (CIDR) with Echo/Create
Session/Delete Session/Delete Bearer messages to find live GTP nodes (SGSN/
GGSN/SGW/PGW).

```
(nediscover)> set config gtp/config/EchoRequest.cnf
(nediscover)> set target 10.0.0.0/24
(nediscover)> run
```

**TEID Allocation Discovery** (`1`) — probes how a node allocates TEIDs
(Tunnel Endpoint Identifiers) via Create Session/Modify Bearer/Create Bearer,
using [`gtp/config/TeidAllocationDiscover.cnf`](../gtp/config/TeidAllocationDiscover.cnf).

**TEID Predictability** (`2`) — analyzes a file of captured TEIDs (one hex
value per line, at least 6) and reports whether the target's TEID generation
algorithm is predictable:

```
(teidpredict)> set config /path/to/teids.hex
(teidpredict)> run
```

### 1) Fraud

**Tunnel Hijack** (`0`) — sends a spoofed `ModifyBearerRequest` to redirect
an existing subscriber's GTP tunnel to an attacker-controlled SGW/PGW,
enabling data interception. Config:
[`gtp/config/TunnelHijack.cnf`](../gtp/config/TunnelHijack.cnf) (needs the
victim's known `teid`/`sqn` and the new SGW's `source_ip`).

### 2) Denial of Service

**Massive DoS** (`0`) — mass subscriber detachment via
Delete Session/Delete Bearer, using
[`gtp/config/MassiveDoS.cnf`](../gtp/config/MassiveDoS.cnf).

**User DoS** (`1`) — same mechanism targeted at a single subscriber, using
[`gtp/config/UserDoS.cnf`](../gtp/config/UserDoS.cnf).

Example:

```
(massive-dos)> set config gtp/config/MassiveDoS.cnf
(massive-dos)> set target 10.0.0.5/32
(massive-dos)> run
```

---

## Diameter module

**Menu path:** `2) Diameter`. Diameter is the 4G/LTE signaling protocol
(S6a/S6d, TS 29.272) used between the MME and the HSS on the LTE roaming
interconnect. Every attack first performs a CER/CEA capabilities-exchange
handshake (RFC 6733) before sending its S6a request. Configs live in
[`diameter/config/`](../diameter/config).

### 0) Information Gathering — Peer Discovery

Sweeps `target` (CIDR or single host) with a Diameter CER (Capabilities-
Exchange-Request); a peer that answers CEA is a live Diameter node, and the
response's advertised Vendor-Specific-Application-Id reveals whether it
speaks S6a.

```
(peer-discover)> set config diameter/config/PeerDiscovery.cnf
(peer-discover)> set target 10.0.0.0/24
(peer-discover)> run
```

### 1) Location Tracking — Authentication Info (AIR)

Sends an `Authentication-Information-Request` for the IMSI configured in
`[IES]`; a non-hardened HSS answers with EPS authentication vectors
(RAND/AUTN/XRES/KASME material) — full subscriber authentication data.

```
(air)> set config diameter/config/AuthInfo.cnf
(air)> set target 10.0.0.5
(air)> run
```

Relevant fields in [`AuthInfo.cnf`](../diameter/config/AuthInfo.cnf):
`imsi`, `mcc`, `mnc`, `num_vectors`, plus the peer identity fields shared by
all Diameter attacks (`origin_host`, `origin_realm`, `dest_realm`,
`dest_host`).

### 2) Interception — Update Location (ULR)

Sends an `Update-Location-Request` claiming to be the subscriber's serving
MME. If the HSS accepts it, subsequent paging/SMS/data-session signaling for
that subscriber routes to the attacker's `origin_host` — the Diameter
analogue of the SS7 UpdateLocation attack.

```
(ulr)> set config diameter/config/UpdateLocation.cnf
(ulr)> set target 10.0.0.5
(ulr)> run
```

### 3) Denial of Service — Subscriber DoS

Detaches the subscriber configured in `[IES].imsi` via either:

- `set mode cancel` (default) — `Cancel-Location-Request` with a
  subscription-withdrawal cancellation type, forcing a full detach.
- `set mode purge` — `Purge-UE-Request`, marking the UE purged in the HSS
  (it must fully re-Attach).

```
(s6a-dos)> set config diameter/config/SubscriberDoS.cnf
(s6a-dos)> set target 10.0.0.5
(s6a-dos)> set mode purge
(s6a-dos)> run
```

---

## SIP module

**Menu path:** `3) SIP`. SIP is used in the IMS/VoLTE access layer (and, per
the SIP-T extension, to carry SS7 ISUP over VoIP interconnects). All
attacks run over UDP; configs live in [`sip/config/`](../sip/config).

### 0) Information Gathering

**OPTIONS Discovery** (`0`) — the SIP equivalent of a ping-sweep: an
`OPTIONS` request to each host in `target` (CIDR) confirms it's a live SIP
node without opening a dialog, and often discloses the node's software via
`Server`/`User-Agent`.

```
(options-discover)> set config sip/config/OptionsDiscovery.cnf
(options-discover)> set target 10.0.0.0/24
(options-discover)> run
```

**REGISTER Enumeration** (`1`) — sends `REGISTER` for every extension in the
`ext_start`..`ext_end` range configured in
[`RegisterEnum.cnf`](../sip/config/RegisterEnum.cnf). A `401`/`407`
challenge means the identity is provisioned; a `404` means it isn't — a
classic subscriber-enumeration oracle.

```
(register-enum)> set config sip/config/RegisterEnum.cnf
(register-enum)> set target 10.0.0.10
(register-enum)> run
```

### 1) Interception — INVITE Spoofing

Sends an `INVITE` whose `From` / `P-Asserted-Identity` claims to be a
different subscriber (`spoofed_user` in
[`InviteSpoof.cnf`](../sip/config/InviteSpoof.cnf)) than the one actually
sending it. A `403` means the core validated the asserted identity; a
`1xx`/`2xx` means Caller-ID spoofing succeeded.

```
(invite-spoof)> set config sip/config/InviteSpoof.cnf
(invite-spoof)> set target 10.0.0.10
(invite-spoof)> run
```

### 2) Denial of Service — INVITE Flood

Sends `count` (in [`InviteFlood.cnf`](../sip/config/InviteFlood.cnf))
unique INVITE requests to exhaust the target's call-state resources.

```
(invite-flood)> set config sip/config/InviteFlood.cnf
(invite-flood)> set target 10.0.0.10
(invite-flood)> run
```

---

## 5G module

**Menu path:** `4) 5G`. Covers the two 5G-core interconnect surfaces: PFCP
on the N4 reference point (SMF↔UPF) and the Service-Based Architecture (SBA)
over HTTP/2. Configs live in [`fiveg/config/`](../fiveg/config). The SBA
attacks require the optional `httpx[http2]` dependency (see
[prerequisites](PREREQUISITES.md#3-python-dependencies)).

### 0) Information Gathering

**PFCP Node Discovery** (`0`) — sweeps `target` (CIDR) on UDP 8805 with
PFCP Heartbeat and Association Setup requests to find live UPF/SMF nodes.

```
(pfcp-discover)> set config fiveg/config/PfcpNodeDiscovery.cnf
(pfcp-discover)> set target 10.0.0.0/24
(pfcp-discover)> run
```

**NRF NF Discovery** (`1`) — queries the NRF's `Nnrf_NFDiscovery` service
(with or without an OAuth2 token, per
[`NrfDiscovery.cnf`](../fiveg/config/NrfDiscovery.cnf)) for every standard
5G network-function type (AMF, SMF, UPF, AUSF, UDM, PCF, SEPP, ...) and
reports how many instances of each are disclosed.

```
(nrf-discover)> set config fiveg/config/NrfDiscovery.cnf
(nrf-discover)> run
```

(`target`/`NrfDiscovery.cnf`'s `host`/`port`/`scheme` together determine the
NRF's base URL; leave `token` blank to test unauthenticated discovery.)

### 1) Service Based Architecture (SBA) — NF Unauthorized Access

Probes a specific NF service endpoint (`service_path` in
[`NfAccess.cnf`](../fiveg/config/NfAccess.cnf)) first **without** a token,
then with one if configured — checking whether the SBI enforces OAuth2
authorization (TS 33.501). A `2xx` on the token-less request is a finding.

```
(nf-access)> set config fiveg/config/NfAccess.cnf
(nf-access)> run
```

### 2) Denial of Service — PFCP Session DoS

Targets a UPF's N4 session state, in one of two modes
(configured via `[SESSION]` in
[`PfcpSessionDoS.cnf`](../fiveg/config/PfcpSessionDoS.cnf)):

- `set mode establish` (default) — floods Session Establishment Requests to
  exhaust the UPF's session table.
- `set mode delete` — sends Session Deletion Requests across a range of
  SEIDs to tear down existing subscriber sessions.

```
(pfcp-dos)> set config fiveg/config/PfcpSessionDoS.cnf
(pfcp-dos)> set target 10.0.0.5
(pfcp-dos)> set mode delete
(pfcp-dos)> run
```

---

## Config file format reference

All `.cnf` files use the `configobj` INI-like format with two conventional
sections:

```ini
[GENERIC]
# transport / peer / local-identity parameters
port = ...
target-independent settings...

[IES]        # or [SESSION] for 5G PFCP session attacks
# subscriber / message-specific parameters
imsi = ...
```

- `target` is **not** set in the `.cnf` file — it's always set at runtime
  via `set target <value>` in the attack shell, so the same config can be
  reused against different hosts/subnets.
- Comments start with `#`.
- Every shipped template under `gtp/config/`, `diameter/config/`,
  `sip/config/`, and `fiveg/config/` is annotated with its accepted fields
  and their meaning — copy one and edit it rather than writing from scratch.

---

## Output files

Discovery/enumeration attacks (GTP Nodes Discovery, TEID Allocation
Discovery, Diameter Peer Discovery, SIP OPTIONS Discovery, SIP REGISTER
Enumeration, PFCP Node Discovery, NRF NF Discovery) write their findings to
a CSV file, controlled by the shell's `output` option
(`set output <path>`, default `results.csv` or an attack-specific default
like `pfcp_nodes.csv`). Point-attacks (AIR, ULR, Subscriber DoS, INVITE
Spoof/Flood, PFCP Session DoS, NF Access) print their result inline and
don't produce a file.

---

## Practicing safely: mock targets

You don't need a real telecom core to exercise every attack — GTP,
Diameter, SIP, and PFCP are all plain UDP/TCP protocols. The snippets below
stand up a minimal mock peer on `127.0.0.1` using only the Python standard
library, so you can `run` any attack above against `localhost` and see it
work before pointing it at a lab core or authorized target.

### Mock PFCP node (Heartbeat / Association Setup)

```python
# mock_upf.py — answers PFCP Heartbeat/Association Setup on UDP 8805
import socket
from fiveg.pfcp_core.node_messages.association import AssociationSetupResponse

srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
srv.bind(('127.0.0.1', 8805))
print('mock UPF listening on 127.0.0.1:8805')
while True:
    data, addr = srv.recvfrom(4096)
    srv.sendto(AssociationSetupResponse(node_id='10.9.9.9').get_message(), addr)
```

Run it, then in SigPloit: `5G > Information Gathering > PFCP Node
Discovery`, `set target 127.0.0.1`, `run`.

### Mock Diameter HSS (CER/CEA + S6a)

```python
# mock_hss.py — answers CER and any S6a request with DIAMETER_SUCCESS
import socket, struct
from diameter.diameter_core.commons.diameter_msg_base import parse_header, DiameterMessage
from diameter.diameter_core.commons import diameter_commons as C
from diameter.diameter_core.commons import avp as A

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 3868))
srv.listen(5)
print('mock HSS listening on 127.0.0.1:3868')

def handle(conn):
    while True:
        head = conn.recv(4)
        if not head:
            return
        length = struct.unpack('!I', b'\x00' + head[1:4])[0]
        rest = b''
        while len(rest) < length - 4:
            rest += conn.recv(length - 4 - len(rest))
        h = parse_header(head + rest)
        ans = DiameterMessage(h['command_code'],
                              application_id=C.APP_S6A if h['command_code'] != C.CMD_CER else 0,
                              request=False)
        ans.add(A.unsigned32(C.AVP_RESULT_CODE, C.DIAMETER_SUCCESS))
        if h['command_code'] == C.CMD_CER:
            ans.add(A.grouped(C.AVP_VENDOR_SPECIFIC_APPLICATION_ID, [
                A.unsigned32(C.AVP_VENDOR_ID, C.VENDOR_3GPP),
                A.unsigned32(C.AVP_AUTH_APPLICATION_ID, C.APP_S6A)]))
        conn.sendall(ans.encode())

while True:
    c, _ = srv.accept()
    handle(c)
```

Run it, then in SigPloit: `Diameter > Information Gathering > Peer
Discovery` (or any S6a attack), `set target 127.0.0.1`, `run`.

### Mock SIP/IMS core (OPTIONS / REGISTER / INVITE)

```python
# mock_ims.py — answers OPTIONS with 200, REGISTER with 401, INVITE with 200
import socket

srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
srv.bind(('127.0.0.1', 5060))
print('mock IMS core listening on 127.0.0.1:5060')
CODES = {'OPTIONS': '200 OK', 'REGISTER': '401 Unauthorized', 'INVITE': '200 OK'}
while True:
    data, addr = srv.recvfrom(8192)
    method = data.decode().split(' ', 1)[0]
    code = CODES.get(method, '501 Not Implemented')
    srv.sendto(('SIP/2.0 %s\r\nContent-Length: 0\r\n\r\n' % code).encode(), addr)
```

Run it, then in SigPloit: any `SIP` attack, `set target 127.0.0.1`, `run`.

Run each mock script from the repository root (`python3 mock_upf.py`, etc.)
so the `fiveg`/`diameter` package imports resolve; stop it with Ctrl-C when
you're done.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `ModuleNotFoundError: No module named 'configobj'` (or similar) right after a successful-looking `pip install` | Almost always a venv/`sudo` mismatch — `sudo pip3 install` installed into the system Python, not your active venv (or vice versa). See [Troubleshooting installation problems](PREREQUISITES.md#troubleshooting-installation-problems). |
| `ModuleNotFoundError: No module named 'httpx'` | Only the 5G SBA attacks (NRF Discovery, NF Access) need it — install with `pip3 install "httpx[http2]"`, or ignore if you only need PFCP attacks. |
| SS7 attack does nothing / `java: command not found` | Install a JRE (see [prerequisites](PREREQUISITES.md#1-system-requirements)). |
| Discovery attack finds nothing | Confirm the target is reachable (`ping`, or check firewall/NAT) and that you're using the right port for the protocol (GTP-C 2123, Diameter 3868, SIP 5060, PFCP 8805) — the shipped configs default to the standard port but can be overridden in the `.cnf`. |
| `set target ...` seems to have no effect | Options are shell-local: `set` inside one attack shell doesn't carry over to a different attack's shell. Re-`set target`/`set config` after `back`-ing into a new attack. |
| Attack raises a Python traceback | The interactive shells catch attack exceptions and print `[-]Error: ... failed to launch, <reason>` — read the reason (usually a bad/missing config path or an unreachable target) rather than a raw traceback. If you see a raw traceback, please file an issue with the exact command sequence. |
