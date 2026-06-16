#!/bin/bash

echo -e "\e[1;31m"
echo "  ███╗   ██╗██╗   ██╗██╗     ██╗         ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗"
echo "  ████╗  ██║██║   ██║██║     ██║         ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║"
echo "  ██╔██╗ ██║██║   ██║██║     ██║         ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║"
echo "  ██║╚██╗██║██║   ██║██║     ██║         ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║"
echo "  ██║ ╚████║╚██████╔╝███████╗███████╗    ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝"
echo "  ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝"
echo -e "\e[0m"
echo -e "\e[1;31m[+] NullShadow v4.0 Setup Starting...\e[0m"

# System packages need root; the venv + pip step must NOT be root so the venv
# is owned by the user. We handle both with sudo for the apt step only.
SUDO=""
if [[ $EUID -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    fi
fi

if command -v apt-get >/dev/null 2>&1; then
    echo -e "\e[1;34m[*] Installing system packages (python3-venv, nmap, whois, git)...\e[0m"
    $SUDO apt-get update -y
    $SUDO apt-get install -y python3 python3-pip python3-venv nmap whois git
else
    echo -e "\e[1;33m[!] apt-get not found — install python3, python3-venv, nmap, whois manually.\e[0m"
fi

# ── Virtual environment (fixes PEP 668 'externally-managed-environment') ──
# Kali 2025.x / Python 3.13 block system-wide pip per PEP 668. A venv is the
# correct, isolated fix and never needs --break-system-packages.
echo -e "\e[1;34m[*] Creating Python virtual environment in ./venv ...\e[0m"
python3 -m venv venv
# shellcheck disable=SC1091
source venv/bin/activate

echo -e "\e[1;34m[*] Upgrading pip and installing Python dependencies into the venv...\e[0m"
pip install --upgrade pip
pip install -r requirements.txt

echo -e "\e[1;34m[*] Creating directories...\e[0m"
mkdir -p reports null_db models

echo -e "\e[1;34m[*] Setting up configuration...\e[0m"
if [ ! -f config/config.py ]; then
    cp config/config.example.py config/config.py
    echo -e "\e[1;32m[+] Created config/config.py from template.\e[0m"
else
    echo -e "\e[1;34m[*] config/config.py already exists.\e[0m"
fi

echo ""
echo -e "\e[1;32m[+] NullShadow v4.0 is ready.\e[0m"
echo ""
echo -e "\e[1;33m[!] NullShadow runs 100%% local/free by default (no API key needed).\e[0m"
echo -e "\e[1;33m[!] For real local AI responses, install Ollama and pull a model:\e[0m"
echo -e "    curl -sSfL https://ollama.com/install.sh | sh && ollama pull llama3.1:8b"
echo -e "\e[1;33m[!] Cloud AI keys are OPTIONAL — set them in config/config.py only if desired.\e[0m"
echo ""
echo -e "\e[1;36m[i] IMPORTANT: activate the venv before running:\e[0m"
echo -e "    source venv/bin/activate"
echo -e "\e[1;31m[>] Launch:           python3 main.py\e[0m"
echo -e "\e[1;31m[>] Defensive monitor: python3 main.py --monitor <target>\e[0m"
echo -e "\e[1;31m[>] Dashboard:        python3 dashboard.py   (http://127.0.0.1:8077)\e[0m"
