#!/bin/bash

echo -e "\e[1;31m"
echo "  ███╗   ██╗██╗   ██╗██╗     ██╗         ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗"
echo "  ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝"
echo -e "\e[0m"
echo -e "\e[1;31m[+] NullShadow Setup Starting...\e[0m"

if [[ $EUID -ne 0 ]]; then
   echo -e "\e[1;33m[!] Run as root: sudo ./setup.sh\e[0m"
   exit 1
fi

echo -e "\e[1;34m[*] Updating system...\e[0m"
apt-get update -y

echo -e "\e[1;34m[*] Installing system packages...\e[0m"
apt-get install -y python3 python3-pip nmap

echo -e "\e[1;34m[*] Installing Python dependencies...\e[0m"
pip3 install rich requests scapy beautifulsoup4 python-nmap phonenumbers \
    python-whois reportlab anthropic openai --break-system-packages

echo -e "\e[1;34m[*] Creating directories...\e[0m"
mkdir -p reports database

echo ""
echo -e "\e[1;32m[+] NullShadow is ready.\e[0m"
echo ""
echo -e "\e[1;33m[!] Add your AI API keys (optional):\e[0m"
echo -e "    export ANTHROPIC_API_KEY='your-claude-key'"
echo -e "    export GEMINI_API_KEY='your-gemini-key'"
echo -e "    export OPENAI_API_KEY='your-openai-key'"
echo ""
echo -e "\e[1;31m[>] Launch: python3 main.py\e[0m"
