# SigPloit

**SigPloit** is a signaling security testing framework for Telecom Security
professionals and researchers, built to pentest and exploit vulnerabilities
in the signaling protocols used across mobile operator networks —
**2G/3G (SS7)**, **3G/4G data (GTP)**, **4G signaling (Diameter)**, **4G IMS/
VoLTE (SIP)**, and the **5G core (SBA/HTTP2 & PFCP)** — regardless of the
generation in use.

SigPloit is referenced in GSMA document **FS.07 "SS7 and Sigtran Network
Security"**. For background on the telecom architectures being tested, see
the [Welcome to SigPloit wiki](https://github.com/SigPloiter/SigPloit/wiki/1--Welcome-to-SigPloit).

> **New here?** Jump straight to [`docs/PREREQUISITES.md`](docs/PREREQUISITES.md)
> to get set up, then [`docs/USAGE.md`](docs/USAGE.md) for a full walkthrough
> of every attack.

---

## Contents

- [What it does](#what-it-does)
- [Module status](#module-status)
- [Quick start](#quick-start)
- [Documentation](#documentation)
- [Project structure](#project-structure)
- [Responsible use](#responsible-use)
- [Contributors](#contributors)
- [License](#license)

---

## What it does

Every attack:

- Is implemented natively in Python 3 (SS7 drives bundled, purpose-built
  Java payloads; everything else — GTP, Diameter, SIP, 5G — is a from-scratch
  protocol implementation, not a wrapper around a third-party SS7/Diameter
  stack).
- Is driven by an interactive, Metasploit-style CLI shell
  (`show options` / `set` / `run` / `back` / `help`), with per-attack
  `.cnf` configuration templates provided.
- Prints a **recommendation** on completion — the remediation guidance to
  hand to the operator alongside the finding.

## Module status

| Module | Generation | Transport | Attacks | Status |
|---|---|---|---|---|
| **SS7** | 2G/3G | SIGTRAN / M3UA (via bundled jSS7-based `.jar`s) | Location Tracking (5), Interception (1), Fraud & Info (4), DoS (1) | ✅ Implemented |
| **GTP** | 3G/4G data | UDP (GTP-C, port 2123) | Node Discovery, TEID Allocation Discovery, TEID Predictability, Tunnel Hijack, Massive DoS, User DoS | ✅ Implemented (GTPv2; GTPv1 pending) |
| **Diameter** | 4G signaling | TCP or SCTP (port 3868), S6a/S6d | Peer Discovery, Authentication Info (AIR), Update Location (ULR), Subscriber DoS (CLR/PUR) | ✅ Implemented |
| **SIP** | 4G IMS/VoLTE | UDP (port 5060) | OPTIONS Discovery, REGISTER Enumeration, INVITE Spoofing, INVITE Flood | ✅ Implemented |
| **5G** | 5G Core | UDP (PFCP, port 8805) + HTTP/2 (SBA/SBI) | PFCP Node Discovery, PFCP Session DoS, NRF NF Discovery, NF Unauthorized Access | ✅ Implemented |
| **Reporting** | — | — | Consolidated report of tests run + recommendations | 🚧 Planned |

Full per-attack detail, menu paths, and example commands are in
[`docs/USAGE.md`](docs/USAGE.md).

## Quick start

```bash
# 1. system deps (Debian/Ubuntu — see docs/PREREQUISITES.md for other distros)
sudo apt-get install -y python3 python3-pip default-jre lksctp-tools build-essential

# 2. get the code
git clone https://github.com/DUptain1993/SigPloit.git
cd SigPloit

# 3. python deps — into a venv (recommended; avoids install/run environment mismatches)
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 4. run it (same shell, venv still active)
python3 sigploit.py
```

> Installing with `sudo pip3 install ...` instead works too, but **don't mix
> it with an active venv** — see
> [`docs/PREREQUISITES.md`](docs/PREREQUISITES.md#3-python-dependencies) if
> you hit `ModuleNotFoundError` right after a pip install that said it
> succeeded.

You'll land on the main menu:

```
0) SS7        2G/3G Voice and SMS attacks
1) GTP        3G/4G Data attacks
2) Diameter   4G Data attacks
3) SIP        4G IMS attacks
4) 5G         5G Core (SBA/HTTP2 & PFCP/N4) attacks
```

Every submenu supports `back` to go up a level and `quit`/`exit`/Ctrl-C to
leave SigPloit. See [`docs/USAGE.md`](docs/USAGE.md#the-interactive-cli-model)
for the full command reference (`show options`, `set`, `run`, ...) and a
walkthrough of every attack.

No live network to test against? [`docs/PREREQUISITES.md`](docs/PREREQUISITES.md#5-optional-the-virtual-lab-no-live-telecom-access-required)
and [`docs/USAGE.md`](docs/USAGE.md#practicing-safely-mock-targets) cover the
bundled SS7 test servers and drop-in mock GTP/Diameter/SIP/PFCP peers you can
run entirely on `localhost`.

## Documentation

| Doc | Covers |
|---|---|
| [`docs/PREREQUISITES.md`](docs/PREREQUISITES.md) | OS/runtime requirements, installing Python & system dependencies, which package each module needs, troubleshooting install failures, the virtual lab. |
| [`docs/USAGE.md`](docs/USAGE.md) | Launching SigPloit, the CLI shell model, a full menu map, a per-attack walkthrough (menu path, config fields, example commands) for every module, the `.cnf` format, output files, and safe local-testing recipes. |
| [`docs/NETWORK_ACCESS.md`](docs/NETWORK_ACCESS.md) | How to get **legitimate, authorized** access to a real interconnect/operator network to test against — engaging an operator directly, going through a GRX/IPX carrier, GSMA's coordination role, and a pre-engagement checklist. |

## Project structure

```
SigPloit/
├── sigploit.py          # Main entry point / top-level menu
├── ss7main.py            ss7/            SS7 (2G/3G) — Java-jar-backed attacks
├── gtpmain.py             gtp/           GTP (3G/4G data) — pure-Python GTPv2-C stack
├── diametermain.py        diameter/      Diameter (4G, S6a) — pure-Python RFC 6733 + TS 29.272 stack
├── sipmain.py             sip/           SIP (4G IMS/VoLTE) — pure-Python RFC 3261 stack
├── fivegmain.py           fiveg/         5G Core — pure-Python PFCP (TS 29.244) + HTTP/2 SBA client
├── Testing/               Java server-side simulators for practicing SS7 attacks in a lab
└── docs/                  Prerequisites & usage documentation
```

Each protocol package follows the same internal layout: a `*_core/`
(or `attacks/` + `commons/`) subpackage implementing the protocol's message
encoding, an `attacks/` subpackage with the actual exploit logic, a
`config/` directory of `.cnf` templates, and a set of interactive shell
modules (`info.py`, `dos.py`, ...) wired into the module's `*main.py` menu.

## Responsible use

SigPloit sends real, standards-compliant signaling messages. Only run it
against a network you own/control or one you have explicit written
authorization to test — several attacks (GTP/Diameter/SIP/PFCP DoS) can
disrupt real subscriber service if pointed at production infrastructure
without authorization. See [`docs/USAGE.md#responsible-use`](docs/USAGE.md#responsible-use)
for details, the [virtual lab](docs/PREREQUISITES.md#5-optional-the-virtual-lab-no-live-telecom-access-required)
for how to practice safely, and
[`docs/NETWORK_ACCESS.md`](docs/NETWORK_ACCESS.md) for how to obtain
legitimate access to a real network when you're ready to move beyond the lab.

## Contributors

- Rosalia D'Alessandro
- Ilario Dal Grande

## License

[MIT](LICENSE)
