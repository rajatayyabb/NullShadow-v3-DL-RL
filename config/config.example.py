import os

# ─── AI API KEYS ───────────────────────────────────────────────
# Get Claude key  → https://console.anthropic.com
# Get Gemini key  → https://aistudio.google.com/app/apikey
# Get OpenAI key  → https://platform.openai.com/api-keys

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY    = os.getenv("OPENAI_API_KEY",    "")
GEMINI_API_KEY    = os.getenv("GEMINI_API_KEY",    "")

# ─── THREAT INTEL API KEYS (optional) ─────────────────────────
VIRUSTOTAL_API_KEY  = os.getenv("VIRUSTOTAL_API_KEY",  "")
SHODAN_API_KEY      = os.getenv("SHODAN_API_KEY",      "")
HIBP_API_KEY        = os.getenv("HIBP_API_KEY",        "")
ABUSEIPDB_API_KEY   = os.getenv("ABUSEIPDB_API_KEY",   "")

# ─── TOOL SETTINGS ─────────────────────────────────────────────
DEFAULT_AI         = "claude"
SCAN_TIMEOUT       = 30
MAX_SUBDOMAINS     = 200
REPORT_OUTPUT_DIR  = os.path.join(os.path.dirname(__file__), '..', 'reports')
DB_PATH            = os.path.join(os.path.dirname(__file__), '..', 'null_db', 'nullshadow.db')

# ─── SUBDOMAIN WORDLIST ────────────────────────────────────────
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "vpn", "remote", "portal", "blog", "shop", "store", "app",
    "mobile", "cdn", "static", "media", "images", "files", "download",
    "upload", "secure", "login", "auth", "oauth", "dashboard", "panel",
    "support", "help", "docs", "wiki", "forum", "community", "chat",
    "smtp", "pop", "imap", "mx", "ns1", "ns2", "dns", "git", "gitlab",
    "jenkins", "jira", "confluence", "sonar", "grafana", "kibana",
    "elasticsearch", "redis", "mysql", "postgres", "mongo", "backup",
]
