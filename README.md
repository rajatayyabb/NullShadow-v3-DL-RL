<div align="center">

```
  ███╗   ██╗██╗   ██╗██╗     ██╗         ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
  ████╗  ██║██║   ██║██║     ██║         ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
  ██╔██╗ ██║██║   ██║██║     ██║         ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
  ██║╚██╗██║██║   ██║██║     ██║         ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
  ██║ ╚████║╚██████╔╝███████╗███████╗    ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
  ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝
```

**AI-Powered Autonomous Penetration Testing Framework**

[![Version](https://img.shields.io/badge/version-3.0%20(DL%2FRL%20Enhanced)-red.svg?style=for-the-badge)](https://github.com/rajatayyabb/NullShadow)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg?style=for-the-badge)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux%20%7C%20Ubuntu-black.svg?style=for-the-badge)](https://www.kali.org/)

*Developed by **Tayyab** — 
</div>

---

## 🖤 What is NullShadow v3.0?

**NullShadow v3.0** is an advanced evolution of the original framework, designed to meet **DARPA AIxCC** standards. It transitions from traditional LLM orchestration to a hybrid architecture featuring **Deep Learning (DL)** for vulnerability discovery and **Reinforcement Learning (RL)** for autonomous attack path optimization.

It combines traditional recon and exploitation tools with cutting-edge AI analysis (Claude, GPT-4, Gemini) and on-device deep learning models to automatically scan targets, identify vulnerabilities, and generate professional PDF reports.

---

## ⚡ New v3.0 Features (DL/RL Enhanced)

### 🧠 Deep Learning Engine
- **Vulnerability Scoring:** On-device scoring of vulnerabilities using simulated Graph Neural Networks (GNNs).
- **Binary Analysis:** Feature extraction and analysis of binary code and firmware.
- **Contextual Threat Assessment:** Real-time risk scoring (0-100%) based on aggregated scan data.

### 🚀 Autonomous Orchestrator (RL-Ready)
- **Agentic Decision-Making:** Autonomously decides the next best action based on current findings.
- **Attack Path Optimization:** Prioritizes high-impact actions to reach a "shell" faster.
- **State Management:** Maintains a comprehensive view of the target's security posture.

### 💡 IoT & Firmware Security
- **Firmware Analysis:** Specialized DL-based analysis for IoT firmware images.
- **Neural Fuzzing:** GAN-based fuzzing for IoT protocols (MQTT, CoAP, Zigbee).
- **Anomaly Detection:** Identifies malicious patterns in IoT traffic.

---

## 🆕 NullShadow v4.0 Additions

v4.0 pivots NullShadow from a one-shot offensive scanner toward a **continuous,
defensive attack-surface monitoring** tool — the kind of capability used in blue-team/SOC
contexts — while keeping every existing v3.0 tool intact (all additions are additive).

| Area | What it adds |
| :--- | :--- |
| **Findings schema + NVD enrichment** | Normalized per-finding records in a new `findings` table; live CVE severity/CVSS from the NVD API with local caching (`cve_cache`) and rate-limit backoff. `modules/intel/nvd_lookup.py` |
| **Guided Remediation** | For every finding: plain-language explanation, CWE/OWASP mapping, severity context, general fix steps and a **generic** secure-pattern snippet. Defensive only — no exploit code. Menu **[35]**, included in PDF reports. `modules/intel/remediation.py` |
| **Scan Diff** | Compare two scans of the same target: new / resolved / changed findings + posture delta. Menu **[34]**. `modules/intel/scan_diff.py` |
| **Exploit reference mapping** | Looks up known public exploit references (Metasploit module paths) for a CVE from a curated **offline** map — informational only. `modules/intel/exploit_refs.py` |
| **MCP Server** | Exposes `port_scan, vulnerability_scan, subdomain_enum, dns_recon, whois_lookup, hash_identify_crack, jwt_analyze` as MCP tools for Claude Desktop & other MCP clients. `mcp_server.py` |
| **Risk-weighted monitoring + dashboard** | `--monitor` mode scores security posture (0–100), flags **ALERT/OK** vs the previous run, and a read-only Flask dashboard charts posture over time. `dashboard.py` |
| **Robust WHOIS (Phase 0.2)** | RDAP via the IANA bootstrap registry resolves non-generic TLDs (.fr, .br, .edu, …), not just com/net/org/io. `modules/intel/rdap_lookup.py` |

### 🛡 Defensive monitoring + dashboard (Phase 6)

```bash
# Run one monitoring pass: recon → posture score → ALERT/OK (linked to the target)
python3 main.py --monitor example.com

# Read-only dashboard (localhost only): posture-over-time, severity breakdown,
# recent ALERT/OK runs, and per-finding remediation drill-down
python3 dashboard.py        # → http://127.0.0.1:8077
```

**Schedule continuous monitoring** with cron (no custom scheduler — it's a config task):

```cron
# every 6 hours, from the project dir, using the venv python
0 */6 * * * cd /path/to/NullShadow && ./venv/bin/python main.py --monitor example.com >> monitor.log 2>&1
```

…or a **systemd timer** (`scripts/systemd/`) running the same command every 6/24 hours.
Each monitoring run creates a new `scan_id` linked to the same target, so Scan Diff can
compare consecutive runs and the dashboard shows the before/after posture story.

### 🔌 MCP server (Phase 4)

```bash
source venv/bin/activate
pip install mcp                # if not already installed
python3 mcp_server.py          # stdio transport
```

Register it with Claude Desktop using `tools/claude_desktop_config.json` (update the
absolute paths, then restart Claude Desktop). The CLI (`main.py`) remains fully usable
standalone — the MCP server is an additional interface, not a replacement.

---

## 💀 All Pentesting Modules

| Category | Modules |
| :--- | :--- |
| **Pentesting** | Port Scanner, Vuln Scanner, Host Discovery, IP Pinger, Dir Bruteforcer, SSL/TLS Auditor, Hash ID & Cracker, JWT Analyzer, Subdomain Enum, DNS Recon, HTTP Header Analyzer |
| **OSINT** | Domain WHOIS, Username Tracker, IP Geolocation, Phone Lookup, Email Harvester, CVE Search |
| **AI & Utilities** | URL Phishing Analyzer, Website Cloner, Cookie Auditor, Network Info, Password Generator, **DL Firmware Analysis**, **Neural Fuzz IoT**, **AUTO PENTEST (DL/RL)** |

---

## 🚀 Installation

### Prerequisites
- Kali Linux / Ubuntu / Debian
- Python 3.8+
- Root privileges

### Quick Setup (uses a virtual environment — fixes PEP 668)

Kali 2025.x / Python 3.13 block system-wide `pip` ("externally-managed-environment",
PEP 668). NullShadow installs into an isolated **virtual environment** instead, so no
`--break-system-packages` hacks are needed.

```bash
git clone https://github.com/rajatayyabb/NullShadow-v3-DL-RL.git
cd NullShadow-v3-DL-RL
chmod +x setup.sh
./setup.sh                 # creates ./venv, installs deps, copies config
```

`setup.sh` installs system packages (nmap, whois) with `sudo` for that step only,
then creates `./venv` owned by your user. To install manually instead:

```bash
sudo apt-get install -y python3-venv nmap whois
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp config/config.example.py config/config.py
```

### Launch (activate the venv first)
```bash
source venv/bin/activate            # every new shell
python3 main.py                     # interactive menu (26 tools)
python3 main.py --monitor <target>  # one defensive monitoring pass (Phase 6)
python3 dashboard.py                # read-only dashboard → http://127.0.0.1:8077
```

> Zero configuration required: NullShadow works out of the box with **no API key**
> via the local AI engine's rule-based fallback. Add Ollama (below) for real local
> AI responses, or cloud keys (optional) for cloud AI.

### Local AI (development mock)

If you don't have a local LLM service running, use the included lightweight mock server for development and testing. This mock implements the minimal endpoints expected by NullShadow:

- `GET /api/health` -> returns HTTP 200 with `{ "status": "ok" }`
- `POST /api/chat` -> accepts `{ "model": "...", "messages": [...] }` and returns `{ "message": { "content": "..." } }`

To run the mock server (no dependencies required):

```bash
python3 scripts/local_ai_server.py
```

Quick tests:

```bash
curl http://localhost:11434/api/health

curl -s -X POST http://localhost:11434/api/chat -H "Content-Type: application/json" \
  -d '{"model":"test","messages":[{"role":"user","content":"hello"}]}'
```

When the mock server is running, start NullShadow with `python3 main.py` and the banner will indicate `Local AI server` when reachable.

---

## Ollama (recommended for company demo)

Use Ollama to host a local model server that NullShadow can query at `LOCAL_AI_URL` (default port `11434`). Below are example commands for a Linux demo environment.

1) Install Ollama (official installer):

```bash
curl -sSfL https://ollama.com/install.sh | sh
```

2) Pull a model (recommended local models below):

```bash
ollama pull llama3.1:8b      # good general default (~5 GB)
# alternatives:
ollama pull qwen2.5:7b       # strong reasoning (~5 GB)
ollama pull deepseek-coder:6.7b   # code/security oriented (NullShadow default model)
ollama pull llama3.2:3b      # lightweight, low-RAM machines (~2 GB)
```

**Approximate hardware:** a 7–8B model needs ~8 GB RAM (CPU-only works but is slow);
a 3B model runs comfortably in ~4 GB. A GPU is optional but much faster.

> **Why this matters (Phase 0.4):** without a running Ollama server, AI Chat falls
> back to a generic rule-based assistant, so every answer looks the same regardless of
> the question. With Ollama running and a model pulled, responses vary per question.
> NullShadow's liveness check probes Ollama's real endpoints (`/api/tags`, `/`) as well
> as the bundled mock's `/api/health`, so the banner correctly shows **● Local AI server**
> when Ollama is up.

3) Start the Ollama server (defaults to port 11434):

```bash
ollama serve &
# or run in foreground for logs:
ollama serve
```

4) Configure NullShadow to point to the local Ollama server (optional env export):

```bash
export LOCAL_AI_URL=http://localhost:11434
export LOCAL_AI_TOKEN="your_ollama_token"  # if required
```

5) Verify health and chat (quick smoke test):

```bash
curl http://localhost:11434/api/health
curl -s -X POST http://localhost:11434/api/chat -H "Content-Type: application/json" -d '{"model":"<model-name>","messages":[{"role":"user","content":"hello"}]}'
```

Notes:
- Replace `<model-name>` with the Ollama model ID you choose.
- For production demos, run Ollama as a systemd service or inside Docker; see `docker-compose.yml` and `scripts/systemd/local_ai.service` for examples included in this repo.


---

## 🔑 API Keys Setup (all OPTIONAL)

**NullShadow needs no API keys.** By default it uses the local AI engine
(`modules/ai/local_ai_engine.py`): Ollama if reachable, otherwise a built-in
rule-based fallback — so AI-touching options ([25] AI Chat, [26] Auto Recon analysis,
[30] Auto Pentest, [35] Guided Remediation) **never** throw an authentication error
with zero configuration.

Cloud keys are optional. If you want cloud AI or extra threat-intel enrichment, add
keys in `config/config.py`:

```bash
cp config/config.example.py config/config.py
nano config/config.py
```

| Service | Link | Required? |
|----|------|----|
| **Local (Ollama)** | https://ollama.com | Recommended (free, local) |
| Claude (Anthropic) | https://console.anthropic.com | Optional |
| Gemini (Google AI Studio) | https://aistudio.google.com/app/apikey | Optional |
| GPT-4 (OpenAI) | https://platform.openai.com/api-keys | Optional |
| NVD CVE API key | https://nvd.nist.gov/developers/request-an-api-key | Optional (raises CVE rate limit) |

---

## 🗂 Project Structure

```
NullShadow/
├── main.py                          ← Entry point (v3.0 Updated)
├── modules/
│   ├── ai/
│   │   ├── ai_engine.py              ← LLM engine
│   │   ├── deep_learning_engine.py   ← NEW: DL scoring engine
│   │   └── orchestrator.py           ← NEW: Autonomous orchestrator
│   ├── pentesting/
│   │   ├── scanner.py                ← Pentest modules
│   │   ├── new_tools.py              ← OSINT/New tools
│   │   └── iot_sec.py                ← NEW: IoT/Firmware security
│   ├── recon/recon_pipeline.py       ← Recon pipeline
│   ├── reporting/report_generator.py ← PDF generator
│   └── osint/osint_tools.py          ← OSINT modules
├── database/db.py                    ← SQLite scan history
├── config/config.py                  ← API keys & settings
├── models/                           ← NEW: Directory for DL models
└── reports/                          ← Generated PDF reports
```

---

## ⚠️ Disclaimer

NullShadow is intended for **educational purposes and authorized security testing only**. Always obtain explicit written permission before scanning any system or network you do not own. The developer is not responsible for any misuse or damage caused by this tool.

**Use responsibly. Hack ethically.**

---

<div align="center">

Made with 🖤 by **Tayyab** & **Manus AI**

*"In the void, shadows speak. In the code, intelligence leads."*

</div>
