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

*Developed by **Tayyab** — Final Year Project 2024*  
*Enhanced by **Manus AI** — v3.0 Deep Learning Upgrade*

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

### Quick Setup
```bash
git clone https://github.com/rajatayyabb/NullShadow-v3-DL-RL.git
cd NullShadow-v3-DL-RL
pip3 install -r requirements.txt
sudo chmod +x setup.sh
sudo ./setup.sh
```

### Launch
```bash
python3 main.py
```

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

## 🔑 API Keys Setup

NullShadow uses AI APIs for intelligent analysis. Add your own keys in `config/config.py`:

```bash
cp config/config.example.py config/config.py
nano config/config.py
```

| AI | Link |
|----|------|
| Claude (Anthropic) | https://console.anthropic.com |
| Gemini (Google AI Studio) | https://aistudio.google.com/app/apikey |
| GPT-4 (OpenAI) | https://platform.openai.com/api-keys |

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
