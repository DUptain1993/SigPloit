# Prerequisites & Installation

This guide covers everything needed to install and run SigPloit: OS and
runtime requirements, Python dependencies (including which ones are needed
by which module), the optional virtual lab for practicing without live
telecom access, and troubleshooting for the most common setup problems.

> New to SigPloit or telecom security in general? Start with the
> [Welcome to SigPloit wiki](https://github.com/SigPloiter/SigPloit/wiki/1--Welcome-to-SigPloit)
> for background on the architectures being tested, then come back here to
> install the tool.

---

## 1. System requirements

| Requirement | Version | Why |
|---|---|---|
| **OS** | Linux (Debian/Ubuntu recommended) | `pysctp` and `lksctp-tools` are Linux-only; the framework is developed and tested on Linux. |
| **Python** | 3.6+ | The entire codebase (CLI, GTP, Diameter, SIP, 5G) is pure Python 3. |
| **Java (JRE)** | 1.7+ | Only required for the **SS7** module, which drives bundled `.jar` attack payloads (jSS7-based). |
| **lksctp-tools** | any recent | SCTP support at the OS level, used for SIGTRAN/M3UA-style transports and optional SCTP transport for Diameter. |
| **pip** | pip3 (matching your Python 3) | Installs the Python dependencies below. |

SigPloit does **not** run on Windows or macOS out of the box (SCTP support
and some socket options are Linux-specific). Use a Linux VM or container if
you're on another OS.

### Install the system packages (Debian/Ubuntu)

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip default-jre lksctp-tools build-essential
```

- `default-jre` satisfies the Java 1.7+ requirement (needed for SS7 only —
  skip it if you will never use the SS7 module).
- `build-essential` is needed because a couple of the Python dependencies
  (`pysctp`) compile a small C extension against `lksctp-tools`.

### Other distributions

- **Fedora/RHEL/CentOS**: `sudo dnf install python3 python3-pip java-11-openjdk lksctp-tools lksctp-tools-devel gcc`
- **Arch**: `sudo pacman -S python python-pip jre-openjdk lksctp-tools base-devel`

---

## 2. Get the code

```bash
git clone https://github.com/DUptain1993/SigPloit.git
cd SigPloit
```

(Or use whichever fork/remote you were given access to.)

---

## 3. Python dependencies

Install everything with:

```bash
sudo pip3 install -r requirements.txt
```

If you'd rather not install as root, use a virtual environment instead:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### What each dependency is for

| Package | Used by | Purpose |
|---|---|---|
| `colorama` | all modules | Cross-platform ANSI color handling for the CLI banner/menus. |
| `pyfiglet` | `sigploit.py` | Renders the SigPloit ASCII banner. |
| `termcolor` | CLI | Colored terminal output helpers. |
| `configobj` | GTP, Diameter, SIP, 5G | Parses the `.cnf` attack configuration files (`[GENERIC]` / `[IES]` / `[SESSION]` sections). |
| `IPy` | GTP, Diameter, PFCP (5G) | Expands a CIDR range (e.g. `10.0.0.0/24`) into individual target addresses for discovery/sweep attacks. |
| `pysctp` | SS7 (SIGTRAN), optional Diameter transport | SCTP socket support. Requires `lksctp-tools` at the OS level to build. |
| `numpy` | GTP TEID Predictability attack | Statistical analysis of captured TEID sequences. |
| `httpx[http2]` | 5G SBA attacks (NRF Discovery, NF Access) | HTTP/2 client for the 5G core's Service Based Interface (SBI). Pulls in `h2` for the HTTP/2 protocol implementation. |

**Module dependency summary** — if you only care about a subset of modules,
here's the minimum you need per module:

| Module | Required packages |
|---|---|
| SS7 | Java 1.7+, `lksctp-tools` (no extra Python packages beyond the CLI basics) |
| GTP | `configobj`, `IPy`, `numpy` (only for TEID Predictability) |
| Diameter | `configobj`, `IPy`, `pysctp` (only if you set `use_sctp = true`; TCP works without it) |
| SIP | `configobj` |
| 5G — PFCP attacks | `configobj`, `IPy` |
| 5G — SBA attacks (NRF Discovery, NF Access) | `httpx[http2]` |

### Troubleshooting `pysctp` / `IPy` install failures

- **`pysctp` fails to build**: this almost always means `lksctp-tools` (and
  its headers) aren't installed. Install `lksctp-tools` (Debian/Ubuntu) or
  `lksctp-tools-devel` (Fedora) and retry.
- **`IPy` fails with a `setuptools`/`install_layout` error**: this is a
  known incompatibility between very old `IPy` releases and modern
  `setuptools`. `requirements.txt` already pins `IPy>=1.1`, which fixes it;
  if you still hit it, upgrade `pip`/`setuptools` first:
  `pip3 install --upgrade pip setuptools wheel`.
- **Building in a minimal/CI container**: install `build-essential` (or your
  distro's C compiler + Python headers package, e.g. `python3-dev`) before
  `pip install`.

---

## 4. Verify the install

```bash
python3 -m py_compile sigploit.py
python3 sigploit.py
```

You should see the ASCII "SigPloit" banner and the main module menu
(`0) SS7`, `1) GTP`, `2) Diameter`, `3) SIP`, `4) 5G`). Type `quit` to exit.

If a module fails to import (e.g. `ModuleNotFoundError: No module named
'httpx'`), only that module's attacks are affected — the rest of the
framework still runs. Install the missing package for the module you need
(see the table above) and relaunch.

---

## 5. Optional: the virtual lab (no live telecom access required)

Live SS7/Diameter/SIP/5G access requires an operator or MVNO agreement, or a
lab environment you control. SigPloit includes two ways to practice safely:

### 5a. Bundled SS7 test servers (`Testing/`)

`Testing/Server/Attacks/` contains Java server-side simulators (source +
prebuilt `.jar`) that emulate the network element on the other end of each
SS7 attack (e.g. an HLR for `SendRoutingInfo`). Each attack has a
`README_Instructions` file documenting the hardcoded PC/IP/port values used
by that simulator, for example:

```
Testing/Server/Attacks/Location_Tracking/SendRoutingInfo_Server/README_Instructions
```

Run the matching server jar, point the client-side attack (in the main
SigPloit menu) at the values in that file, and observe the exchange safely
on a loopback/lab network.

### 5b. Mock servers for GTP / Diameter / SIP / 5G

The GTP, Diameter, SIP, and 5G modules are plain UDP/TCP protocols, so you
can stand up a minimal mock peer with nothing more than Python's standard
library — no telecom-specific server software required. See
[`USAGE.md`](USAGE.md#practicing-safely-mock-targets) for ready-to-run
examples (a mock PFCP/UPF, a mock Diameter HSS, and a mock SIP/IMS core) that
let you exercise every attack end-to-end on `127.0.0.1` before ever pointing
the tool at a real network.

### 5c. Open-source 5G/EPC cores

For more realistic 5G-core and EPC testing, deploy a lab core such as
[free5GC](https://free5gc.org/), [Open5GS](https://open5gs.org/), or the
[OpenAirInterface](https://openairinterface.org/) CN, in an isolated
network/VM, and point the Diameter/PFCP/SBA attacks at it. Setting up those
projects is outside SigPloit's scope — see their own documentation.

---

## 6. Legal notice

SigPloit is intended **only** for authorized security testing: your own
lab/core network, or a network you have explicit written permission to test
(e.g. a signed pentest engagement or roaming-partner agreement). Sending
these messages to production telecom infrastructure you do not own or have
authorization to test is illegal in most jurisdictions and can disrupt real
subscriber service. See [`USAGE.md`](USAGE.md#responsible-use) for more.

---

**Next step:** [`USAGE.md`](USAGE.md) — how to launch SigPloit and drive
each module's attacks.
