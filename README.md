<div align="center">

```
███╗   ██╗██╗   ██╗██╗     ██╗         ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
████╗  ██║██║   ██║██║     ██║         ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
██╔██╗ ██║██║   ██║██║     ██║         ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
██║╚██╗██║██║   ██║██║     ██║         ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
██║ ╚████║╚██████╔╝███████╗███████╗    ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝
```

### AI-Powered Autonomous Security Platform

[![Version](https://img.shields.io/badge/version-4.0-red.svg?style=for-the-badge)](https://github.com/rajatayyabb/NullShadow-v3-DL-RL)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg?style=for-the-badge)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux%20%7C%20Ubuntu-black.svg?style=for-the-badge)](https://www.kali.org/)
[![Stars](https://img.shields.io/github/stars/rajatayyabb/NullShadow-v3-DL-RL?style=for-the-badge&color=yellow)](https://github.com/rajatayyabb/NullShadow-v3-DL-RL/stargazers)

**Free. Self-Hosted. No Data Leaves Your Network.**

*Developed by **Tayyab** | BS Cybersecurity | CASE Institute of Technology*

[📺 Demo Video](#demo) · [🚀 Quick Install](#installation) · [📋 Features](#features) · [🗺️ Roadmap](#roadmap)

</div>

-----

## What is NullShadow?

NullShadow is a **free, self-hosted AI security platform** that gives organizations enterprise-grade vulnerability monitoring, threat intelligence correlation, and AI-guided remediation — without paying for CrowdStrike, Darktrace, or Tenable.

It does two things most security tools don’t:

1. **Continuous defensive monitoring** — runs on a schedule, tracks how your security posture changes over time, alerts when risk increases, and explains exactly how to fix each finding
1. **Compliance evidence generation** — automatically maps findings to ISO 27001, NIST CSF, and PCI DSS controls and generates audit-ready documentation

> “You have been exposed to this critical CVE for 47 days” is more actionable than a list of CVE IDs.

-----

## ✨ What’s New in v4.0

|Feature                             |Description                                                                       |
|------------------------------------|----------------------------------------------------------------------------------|
|🛡️ **Defensive Monitoring Dashboard**|Live posture score, findings by severity, monitoring history with Δ Risk          |
|🕰️ **Security Posture Time Machine** |Calculates exact days exposed per CVE using NVD publish dates + scan history      |
|📊 **CVSS-Weighted Risk Scoring**    |0–100 posture score, Critical CVEs on CISA KEV list trigger CRITICAL alerts       |
|🔍 **NVD CVE Enrichment**            |Every CVE automatically enriched with CVSS score, description, publish date       |
|🔄 **Scan Diff Engine**              |New/resolved/changed findings between scans + risk delta calculation              |
|🧠 **Guided Remediation**            |CWE/OWASP mapping + plain-language explanation + secure config snippet per finding|
|🌐 **IANA RDAP WHOIS**               |Full WHOIS support for all TLDs including .edu.pk, .gov.pk, .com.pk               |
|🔌 **MCP Server**                    |10 tools exposed via Model Context Protocol for AI agent integration              |
|💬 **Local AI via Ollama**           |Full AI analysis with zero API cost — runs entirely on your hardware              |

-----

## 🎯 Features

### Offensive — 37 Tools

<details>
<summary><b>Pentesting (11 tools)</b></summary>

|# |Tool                 |What It Does                                          |
|--|---------------------|------------------------------------------------------|
|01|Port Scanner         |TCP/UDP port scan with service fingerprinting via nmap|
|02|Vulnerability Scanner|CVE detection via nmap NSE scripts                    |
|03|Host Discovery       |ARP/ICMP network sweep                                |
|04|IP Pinger            |ICMP latency and reachability                         |
|05|Dir Bruteforcer      |Multi-threaded web directory enumeration              |
|06|SSL/TLS Auditor      |Cipher suite, cert chain, expiry, TLS version check   |
|07|Hash ID & Cracker    |Hash type identification + wordlist cracking          |
|08|JWT Analyzer         |JWT decode, algorithm weakness detection              |
|09|Subdomain Enumerator |DNS brute-force + passive enumeration                 |
|10|DNS Recon            |A/AAAA/MX/TXT/NS/SOA record retrieval                 |
|11|HTTP Header Analyzer |Security header audit, misconfiguration detection     |

</details>

<details>
<summary><b>OSINT (6 tools)</b></summary>

|# |Tool            |What It Does                                         |
|--|----------------|-----------------------------------------------------|
|12|Domain WHOIS    |IANA RDAP bootstrap — supports all TLDs              |
|13|Username Tracker|30+ platform cross-check (GitHub, Reddit, Instagram…)|
|14|IP Geolocation  |Country, city, ISP, ASN                              |
|15|Phone Lookup    |Carrier, number type, E.164 format                   |
|16|Email Harvester |Domain-based email discovery from public sources     |
|17|CVE Search      |Keyword-based CVE lookup via NVD API                 |

</details>

<details>
<summary><b>AI & Utilities (8 tools)</b></summary>

|# |Tool                 |What It Does                                       |
|--|---------------------|---------------------------------------------------|
|18|URL Phishing Analyzer|AI-scored phishing risk analysis                   |
|19|Website Cloner       |Offline mirror for analysis                        |
|20|Cookie Auditor       |Secure/HttpOnly/SameSite flag checker              |
|21|Network Info         |Interface, IP, gateway, DNS                        |
|22|Password Generator   |Cryptographically random password generation       |
|23|DL Firmware Analysis |Binary scanning for hardcoded credentials/backdoors|
|24|Neural Fuzz IoT      |Malformed packet fuzzing for MQTT/CoAP             |
|25|AI Chat Mode         |Interactive security Q&A                           |

</details>

### Defensive — Continuous Monitoring

|Feature                      |How It Works                                                                            |
|-----------------------------|----------------------------------------------------------------------------------------|
|**Auto Full Recon** `[26]`   |7-phase autonomous recon: WHOIS → Subdomain → Port → Vuln → Geo → ThreatIntel → SSL     |
|**Scan Diff** `[34]`         |Compare any two scans — new findings, resolved findings, changed severity               |
|**Guided Remediation** `[35]`|Per-finding: CWE/OWASP mapping + explanation + remediation steps + secure config snippet|
|**CVE Enrichment** `[36]`    |Enrich all findings with live NVD data — CVSS scores, descriptions, publish dates       |
|**Monitoring Mode**          |Run on a schedule via cron — continuous posture tracking                                |
|**Dashboard**                |Flask web dashboard at localhost:5000 — posture score timeline, severity charts         |

### AI Modes

|Mode            |Backend                                  |Cost       |
|----------------|-----------------------------------------|-----------|
|Local (default) |Ollama — llama3.2:3b / qwen2.5:7b        |**Free**   |
|Cloud (optional)|Claude / GPT-4 / Gemini                  |Pay-per-use|
|MCP Agent       |Any MCP client (Claude Desktop, Odysseus)|Free       |

-----

## 🚀 Installation

### Prerequisites

```bash
# Install nmap (required)
sudo apt install nmap -y

# Install Ollama for free local AI (recommended)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2:3b
```

### Quick Setup

```bash
git clone https://github.com/rajatayyabb/NullShadow-v3-DL-RL.git
cd NullShadow-v3-DL-RL

# Create virtual environment (required on Kali 2025.x)
python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
sudo chmod +x setup.sh && sudo ./setup.sh

python3 main.py
```

### Optional: Start Dashboard

```bash
# In a separate terminal (with venv activated)
python3 dashboard.py
# Open http://localhost:5000
```

### Optional: Connect Claude Desktop via MCP

```bash
# Start MCP server
python3 mcp_server.py

# Add to Claude Desktop config (~/.config/Claude/claude_desktop_config.json):
{
  "mcpServers": {
    "nullshadow": {
      "command": "python3",
      "args": ["/path/to/NullShadow-v3-DL-RL/mcp_server.py"]
    }
  }
}
```

### Optional: API Keys (not required)

All core features work without any API keys. To enable cloud AI analysis:

```bash
cp config/config.example.py config/config.py
nano config/config.py
```

|Provider          |Key                |Link                           |
|------------------|-------------------|-------------------------------|
|Anthropic (Claude)|`ANTHROPIC_API_KEY`|<https://console.anthropic.com>|
|OpenAI (GPT-4)    |`OPENAI_API_KEY`   |<https://platform.openai.com>  |
|Google (Gemini)   |`GEMINI_API_KEY`   |<https://aistudio.google.com>  |

-----

## 🏗️ Architecture

```
NullShadow v4.0
├── main.py                          ← CLI entry point (37 tools)
├── mcp_server.py                    ← MCP server (10 tools for AI agents)
├── dashboard.py                     ← Flask web dashboard
├── modules/
│   ├── ai/
│   │   ├── ai_engine.py             ← Cloud AI (Claude/GPT-4/Gemini)
│   │   ├── local_ai_engine.py       ← Local AI (Ollama + fallback)
│   │   ├── deep_learning_engine.py  ← DL vulnerability scoring
│   │   ├── orchestrator.py          ← RL autonomous orchestrator
│   │   └── rl_engine.py             ← Q-learning attack path optimization
│   ├── pentesting/
│   │   ├── scanner.py               ← Core pentest tools
│   │   ├── new_tools.py             ← Additional tools
│   │   └── iot_sec.py               ← IoT/firmware security
│   ├── osint/osint_tools.py         ← OSINT modules
│   ├── recon/recon_pipeline.py      ← 7-phase autonomous recon
│   ├── reporting/report_generator.py← PDF report generation
│   ├── utilities/util_tools.py      ← Misc utilities
│   └── intel/
│       ├── nvd_lookup.py            ← NVD CVE enrichment
│       ├── scan_diff.py             ← Scan comparison engine
│       ├── risk_score.py            ← CVSS-weighted posture scoring
│       ├── remediation.py           ← AI-guided remediation generation
│       └── threat_feeds.py          ← CISA KEV / OTX / ThreatFox (v5)
└── null_db/db.py                    ← SQLite (scans + findings + CVE cache)
```

-----

## 🔌 MCP Tools

NullShadow exposes 10 tools via Model Context Protocol. Connect any MCP-compatible AI client (Claude Desktop, Odysseus, Cursor, Roo Code):

```
port_scan(target)           → Port scan with service fingerprinting
vulnerability_scan(target)  → CVE detection via nmap NSE scripts  
subdomain_enum(target)      → DNS brute-force subdomain discovery
dns_recon(target)           → Full DNS record retrieval
whois_lookup(domain)        → RDAP-based registrant data
hash_crack(hash)            → Hash identification + wordlist cracking
jwt_analyze(token)          → JWT decode + weakness detection
threat_intel_check(target)  → CISA KEV + OTX + ThreatFox lookup
exposure_analysis(target)   → Days-exposed per CVE (Time Machine)
ai_pentest(target_url)      → AI system vulnerability testing (v5.0)
```

-----

## 🗺️ Roadmap

### v4.0 — Current (Production Ready) ✅

- 37-tool CLI, structured findings DB, NVD CVE enrichment
- CVSS-weighted risk scoring, scan diff engine
- Guided remediation with CWE/OWASP mapping
- Web dashboard with posture score timeline
- MCP server with 10 exposed tools
- Local AI via Ollama (zero cost)

### v5.0 — In Development 🔧

- **Odysseus Integration** — Natural language interface. Type “scan this domain” → AI agent calls tools autonomously
- **Security Posture Time Machine** — Days exposed per CVE visualization
- **Real-Time Threat Intel** — CISA KEV + AlienVault OTX + abuse.ch ThreatFox
- **AI System Pentesting** — Prompt injection scanner, LLM endpoint discovery (OWASP LLM Top 10)
- **Compliance Evidence Generator** — Auto-generate ISO 27001 / NIST CSF / PCI DSS audit documents
- **One-Command Docker Deploy** — `docker-compose up` starts everything

-----

## 📊 Why NullShadow?

|Capability                 |NullShadow|Nessus        |CrowdStrike        |Manual Pentest  |
|---------------------------|:--------:|:------------:|:-----------------:|:--------------:|
|Vulnerability Scanning     |✅         |✅             |✅                  |✅               |
|Continuous Monitoring      |✅         |✅             |✅                  |❌               |
|AI-Guided Remediation      |✅         |❌             |❌                  |❌               |
|Scan Diff (Change Tracking)|✅         |❌             |✅                  |❌               |
|Local AI (No Cloud Cost)   |✅         |❌             |❌                  |❌               |
|MCP Agent Integration      |✅         |❌             |❌                  |❌               |
|ISO 27001 Evidence Report  |✅         |❌             |❌                  |✅               |
|AI System Pentesting       |✅ (v5)    |❌             |❌                  |❌               |
|**Cost**                   |**Free**  |**$3,990+/yr**|**$15/endpoint/mo**|**$500+/report**|

-----

## ⚠️ Disclaimer

NullShadow is intended for **educational purposes and authorized security testing only**. Always obtain explicit written permission before scanning any system or network you do not own. The developer is not responsible for any misuse or damage caused by this tool.

**Use responsibly. Test ethically.**

-----

<div align="center">

Made with 🖤 by **Tayyab**

*BS Cybersecurity | CASE Institute of Technology*

*“In the void, shadows speak. In the code, intelligence leads.”*

⭐ If NullShadow helped you, consider starring the repo

</div>