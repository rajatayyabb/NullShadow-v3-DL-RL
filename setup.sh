#!/bin/bash

echo -e "\e[1;31m"
echo "  ███╗   ██╗██╗   ██╗██╗     ██╗         ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗"
echo "  ████╗  ██║██║   ██║██║     ██║         ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║"
echo "  ██╔██╗ ██║██║   ██║██║     ██║         ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║"
echo "  ██║╚██╗██║██║   ██║██║     ██║         ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║"
echo "  ██║ ╚████║╚██████╔╝███████╗███████╗    ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝"
echo "  ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝"
echo -e "\e[0m"
echo -e "\e[1;31m[+] NullShadow v3.0 Setup Starting...\e[0m"

if [[ $EUID -ne 0 ]]; then
   echo -e "\e[1;33m[!] Run as root: sudo ./setup.sh\e[0m"
   exit 1
fi

echo -e "\e[1;34m[*] Updating system...\e[0m"
apt-get update -y

echo -e "\e[1;34m[*] Installing system packages...\e[0m"
apt-get install -y python3 python3-pip nmap whois git

echo -e "\e[1;34m[*] Installing Python dependencies...\e[0m"
# Check for PEP 668 and use appropriate flags
if grep -q "EXTERNALLY-MANAGED" /usr/lib/python3*/EXTERNALLY-MANAGED 2>/dev/null; then
    echo -e "\e[1;33m[!] Externally managed environment detected. Using --break-system-packages...\e[0m"
    pip3 install -r requirements.txt --break-system-packages --ignore-installed
else
    pip3 install -r requirements.txt
fi

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
echo -e "\e[1;32m[+] NullShadow v3.0 is ready.\e[0m"
echo ""
echo -e "\e[1;33m[!] Add your AI API keys (optional) in config/config.py or export them:\e[0m"
echo -e "    export ANTHROPIC_API_KEY='your-claude-key'"
echo -e "    export GEMINI_API_KEY='your-gemini-key'"
echo -e "    export OPENAI_API_KEY='your-openai-key'"
echo ""
echo -e "\e[1;31m[>] Launch: python3 main.py\e[0m"
