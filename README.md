# BLACKBOX

**Cyber Investigation & Attack Reconstruction Platform**

BLACKBOX is an experimental platform for investigating cyber incidents, analysing
events and reconstructing the sequence of actions inside an isolated lab
environment.

The project explores the principles of Detection Engineering, Digital Forensics,
Incident Response and Threat Hunting.

## Installation

> ⚠️ This is an isolated lab with **vulnerable** targets. Run it only on a trusted
> network, never on a work machine.
> Requirements: **Docker** (running daemon) and a Linux kernel with **BTF**
> (`/sys/kernel/btf/vmlinux`) for the Tetragon eBPF sensor. Python ≥ 3.11.

The engine runs on Docker + Python and is **distribution-agnostic** — the
`install.sh` path works on any Linux (Arch, Debian, Ubuntu, Kali, Fedora…).

### Any Linux — `install.sh`

```bash
git clone https://github.com/ermat175-droid/BLACKBOX
cd BLACKBOX
./install.sh          # venv + dependencies + the `blackbox` command
blackbox doctor       # checks Docker / kernel / Python
blackbox up           # console:  http://127.0.0.1:8000/ui/
```

**Debian / Ubuntu / Kali** — `venv`, `pip` and Docker are separate packages, so
install them once before `install.sh`:

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip docker.io
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"    # then log out and back in
```

**Fedora / RHEL**:

```bash
sudo dnf install -y python3 docker
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"    # then log out and back in
```

On Arch, `python` already bundles `venv`/`pip`, and Docker is the `docker` package.

### Arch Linux — PKGBUILD (pacman-style)

```bash
# natively via pacman, no AUR account needed:
makepkg -si
blackbox up

# or, once the package is published to the AUR:
yay -S blackbox-git
```

### Commands

```text
blackbox up [--lan]   start the console (--lan exposes it to your Wi-Fi)
blackbox down         stop the console
blackbox status       console / sensor / targets state
blackbox open         open the console in a browser
blackbox doctor       check prerequisites
blackbox clean        wipe local case data and lab containers
```

Investigation data (`blackbox.db`, targets, proxy) is stored locally and **never
committed to git** — anyone who clones the repository starts with a clean
database.

## Features

- Synthetic incident scenario generation.
- Event collection and normalization.
- Suspicious-activity detection via detection rules.
- Event correlation by PID, parent PID, timestamps and network attributes.
- Mapping of detected actions to MITRE ATT&CK.
- Incident timeline construction.
- Reconstruction of the action sequence.
- Relationship graph between events and processes.
- AI Investigator to assist analysis.
- Web interface for incident analysis.

## Architecture

```text
BLACKBOX
│
├── Scenario Simulator
│   └── Generate synthetic incidents
│
├── Event Collector
│   └── Receive events
│
├── Event Normalization
│   └── Canonicalize events to one format
│
├── Detection Engine
│   └── Detect suspicious activity
│
├── Correlation Engine
│   └── Link events together
│
├── MITRE ATT&CK Mapping
│   └── Classify techniques
│
├── Timeline Builder
│   └── Reconstruct the sequence of events
│
├── Evidence Graph
│   └── Visualize relationships
│
├── AI Investigator
│   └── Assist with investigation
│
└── Web Dashboard
    └── Investigation interface
```

## Current status

### Implemented

- [x] Base project structure.
- [x] Python + FastAPI backend.
- [x] SQLite event storage.
- [x] SQLAlchemy ORM.
- [x] API to ingest and query events.
- [x] Synthetic scenario BB-001.
- [x] Scenario Simulator that sends test events to the API.
- [x] Base git structure and `.gitignore`.
- [x] Event normalization (canonical format + raw + indexes).
- [x] Normalization built into API ingestion (`POST /events`).
- [x] Collector: processes and network via Tetragon (eBPF, no changes to the target).
- [x] Collector: HTTP requests via a logging proxy, so **any** loaded site is observable.
- [x] Correlation Engine: incident graph (`parent_of`, `spawned_by`,
      `connected_to`), every edge carries a reason.
- [x] Reconstruction Engine: staged attack story (tactic + MITRE technique +
      reason + confidence + event references), `GET /incidents/{case}/reconstruction`.
- [x] Detection + MITRE ATT&CK mapping (detectors in the Reconstruction Engine).
- [x] Investigation Console (`GET /ui`): attack story + graph + timeline +
      evidence panel; RU/EN/KZ languages; collapsible side columns; live updates.
- [x] Incident timeline (`GET /incidents/{case}/timeline`).
- [x] Evidence integrity: tamper-evident hash chain (`GET /integrity`), UI badge.
- [x] Target Manager: load target sites (image / Dockerfile), run them sandboxed
      on 127.0.0.1 with automatic telemetry; GUI `/ui/targets.html`
      (`/targets`, `/sensor`).
- [x] Defender infrastructure: auto asset map + blast radius
      (`/incidents/{id}/infrastructure`, `/impact`); live map in the UI.
- [x] Blind validation against the attacker's log (`/validate`, `attacker_log.py`).
- [x] Defence rule generation (Sigma + Tetragon) from the chain (`/rules`).
- [x] Live attack block (Tetragon enforce, `POST/DELETE /enforce`) with a strict
      safety filter (attack artefacts only, never system shells); visible block counter.
- [x] Signed, self-verifying report (`/report`, `verify_report.py`).
- [x] Offline demo: incident fixture + `scripts/replay.py`.
- [x] Lab: vulnerable CTF machines, telemetry capture verified end-to-end
      against a real attack run.

### In progress

- [ ] Presentation and a backup demo recording for the ORTAQ final.
- [ ] Compose as a target source (multi-container sites).
- [ ] AI Investigator (local LLM explains chains with event citations).

## Tech stack

| Component | Technology |
|---|---|
| Backend | Python, FastAPI |
| Database | SQLite, SQLAlchemy |
| Event format | JSON |
| Detection | Sigma-like rules |
| Sensor | Tetragon (eBPF) |
| AI | Ollama, local LLMs (planned) |
| Frontend | HTML/CSS/JS (no build step) |
| Visualization | Cytoscape.js |
| Environment | Linux, isolated lab |

## Security

BLACKBOX is built as a research lab.

- Synthetic scenarios do not run real commands.
- Test IP addresses are used only as data.
- Experiments against real systems are only performed in your own isolated labs.
- Local databases, secrets and environment configuration must never be committed to git.

## Project goal

Build a platform that can ingest security events, surface suspicious chains of
actions and reconstruct the course of an incident, giving the analyst a clear
picture of what happened.

**BLACKBOX — from raw events to incident reconstruction.**
