import os

# ═══════════════════════════════════════════════════════════════
#  NullShadow v4.0 — Configuration
# ═══════════════════════════════════════════════════════════════
#  NullShadow runs with ZERO configuration by default.
#
#  Out of the box it uses the LOCAL AI engine (modules/ai/local_ai_engine.py):
#    1. If an Ollama server is reachable at LOCAL_AI_URL, it uses that.
#    2. If not, it falls back to a built-in rule-based assistant.
#  Either way, no API key is required and no paid request is ever made.
#
#  Cloud AI keys below are OPTIONAL. They are only used if you explicitly
#  wire in a cloud engine and select it; the default build never calls them.
# ═══════════════════════════════════════════════════════════════

# ─── LOCAL AI (DEFAULT — recommended, zero cost) ──────────────────
# Ollama / OpenAI-compatible local server. This is the default engine.
# Install Ollama (https://ollama.com), then `ollama pull llama3.1:8b`.
# Recommended local models: llama3.1:8b, qwen2.5:7b, deepseek-coder:6.7b
LOCAL_AI_URL    = os.getenv("LOCAL_AI_URL",   "http://localhost:11434")
LOCAL_AI_MODEL  = os.getenv("LOCAL_AI_MODEL", "deepseek-coder:6.7b")
LOCAL_AI_TOKEN  = os.getenv("LOCAL_AI_TOKEN", "")   # only if your server needs auth

# ─── AI API KEYS (OPTIONAL — leave blank to stay 100% local/free) ─
# These are NOT required. With no keys set, NullShadow still works fully
# via the local engine above (Ollama or rule-based fallback).
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

# ─── OSINT API KEYS (optional) ─────────────────────────────────
NUMVERIFY_API_KEY   = os.getenv("NUMVERIFY_API_KEY",   "")  # For phone number lookup

# ─── NVD (CVE) API (optional) ─────────────────────────────────
# The NVD CVE API is free and keyless, but limited to 5 requests / 30s
# without a key. Add a key (https://nvd.nist.gov/developers/request-an-api-key)
# to raise the limit. NullShadow caches CVE lookups locally either way.
NVD_API_KEY         = os.getenv("NVD_API_KEY",         "")

# ─── TOOL SETTINGS ─────────────────────────────────────────────
# DEFAULT_AI = "local" keeps NullShadow free and offline-capable by default.
DEFAULT_AI         = os.getenv("DEFAULT_AI", "local")
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
