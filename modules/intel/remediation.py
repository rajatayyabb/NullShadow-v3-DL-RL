"""
Guided Remediation (brief Section 1.6) — the "best in class" differentiator.

For any finding (from scanner.py, recon_pipeline.py, cve_search, etc.) this module
produces a structured remediation block:

  DOES produce per finding:
    * Plain-language explanation of the issue
    * Relevant CWE and/or OWASP category reference
    * Severity context (CVSS, when a CVE is present)
    * General remediation steps
    * A GENERIC secure-pattern config/code snippet (best practice, not host-specific)

  DOES NOT do:
    * Host-specific patches/config diffs for the actual scanned target
    * Exploit code, working payloads or step-by-step attack instructions
    * Any connection to or modification of the scanned target

The structured block is always built from a built-in knowledge base (so it works
with ZERO AI / zero cost). When an AI engine is available, a constrained,
defensive prompt is added on top for a richer plain-language explanation.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

# Constrained system prompt — defensive only.
REMEDIATION_SYSTEM_PROMPT = (
    "You are a defensive security remediation assistant for the NullShadow framework. "
    "Given a single security finding, you must: (1) explain the issue in plain language, "
    "(2) map it to the most relevant CWE and/or OWASP category, (3) give general, "
    "best-practice remediation steps, and (4) show a GENERIC secure-pattern configuration "
    "or code snippet illustrating the fix. "
    "STRICT RULES: Do NOT produce exploit code, working payloads, or step-by-step attack "
    "instructions. Do NOT produce a host-specific patch or config diff for the scanned "
    "target. Keep all guidance generic and defensive. Be concise and actionable."
)

# ── Built-in remediation knowledge base (rule-based, zero-cost) ──────────
# Each category: matched by keyword, mapped to CWE/OWASP + steps + a generic snippet.
_KB = {
    "weak_tls": {
        "match": ["tls 1.0", "tls 1.1", "sslv", "weak cipher", "weak — upgrade",
                  "ssl/tls", "rc4", "3des", "heartbleed", "poodle", "beast"],
        "title": "Weak TLS / SSL configuration",
        "cwe": "CWE-326: Inadequate Encryption Strength",
        "owasp": "A02:2021 - Cryptographic Failures",
        "explanation": ("The service negotiates outdated TLS versions or weak cipher "
                        "suites. These are vulnerable to downgrade and decryption attacks "
                        "and fail modern compliance baselines."),
        "steps": [
            "Disable SSLv2/SSLv3 and TLS 1.0/1.1; require TLS 1.2 as a minimum and prefer TLS 1.3.",
            "Restrict ciphers to modern AEAD suites (e.g. ECDHE + AES-GCM / CHACHA20-POLY1305).",
            "Enable HSTS so clients only connect over HTTPS.",
            "Renew certificates from a trusted CA and keep TLS libraries patched.",
        ],
        "snippet": ("# nginx — modern TLS baseline\n"
                    "ssl_protocols TLSv1.2 TLSv1.3;\n"
                    "ssl_prefer_server_ciphers on;\n"
                    "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:CHACHA20-POLY1305;\n"
                    "add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains\" always;"),
    },
    "missing_headers": {
        "match": ["missing", "security header", "hsts", "content-security-policy",
                  "x-frame-options", "x-content-type-options", "clickjacking", "csp"],
        "title": "Missing HTTP security headers",
        "cwe": "CWE-693: Protection Mechanism Failure",
        "owasp": "A05:2021 - Security Misconfiguration",
        "explanation": ("Responses are missing hardening headers, leaving the app more "
                        "exposed to clickjacking, MIME sniffing and cross-site scripting."),
        "steps": [
            "Add Strict-Transport-Security, Content-Security-Policy and X-Content-Type-Options.",
            "Add X-Frame-Options: DENY (or a frame-ancestors CSP directive) to stop clickjacking.",
            "Remove version-disclosing headers such as Server and X-Powered-By.",
        ],
        "snippet": ("# Apache — add hardening headers\n"
                    "Header always set X-Content-Type-Options \"nosniff\"\n"
                    "Header always set X-Frame-Options \"DENY\"\n"
                    "Header always set Content-Security-Policy \"default-src 'self'\"\n"
                    "Header unset X-Powered-By"),
    },
    "open_port": {
        "match": ["open port", "port scan", "exposed service", "port "],
        "title": "Exposed network service / open port",
        "cwe": "CWE-668: Exposure of Resource to Wrong Sphere",
        "owasp": "A05:2021 - Security Misconfiguration",
        "explanation": ("A network service is reachable from outside its intended scope. "
                        "Each exposed port enlarges the attack surface."),
        "steps": [
            "Confirm the service is required to be externally reachable; if not, firewall it off.",
            "Restrict access by source IP / VPN and bind services to internal interfaces.",
            "Keep the exposed service patched and require strong authentication.",
        ],
        "snippet": ("# Linux firewall (ufw) — default-deny, allow only what is needed\n"
                    "ufw default deny incoming\n"
                    "ufw allow from 10.0.0.0/8 to any port 22 proto tcp\n"
                    "ufw enable"),
    },
    "jwt_none": {
        "match": ["alg none", "algorithm: none", "no signature verification", "jwt"],
        "title": "Insecure JWT configuration",
        "cwe": "CWE-347: Improper Verification of Cryptographic Signature",
        "owasp": "A02:2021 - Cryptographic Failures",
        "explanation": ("The token accepts the 'none' algorithm or a weak symmetric key, "
                        "allowing forged tokens and authentication bypass."),
        "steps": [
            "Reject the 'none' algorithm; pin an explicit allow-list of strong algorithms.",
            "Use asymmetric signing (RS256/ES256) or a long, high-entropy HMAC secret.",
            "Always verify signature, issuer, audience and expiry server-side.",
        ],
        "snippet": ("# python (PyJWT) — verify with an explicit algorithm allow-list\n"
                    "jwt.decode(token, public_key, algorithms=[\"RS256\"],\n"
                    "           audience=\"my-api\", options={\"require\": [\"exp\", \"iss\"]})"),
    },
    "sql_injection": {
        "match": ["sql injection", "sqli", "sql-injection"],
        "title": "SQL Injection",
        "cwe": "CWE-89: SQL Injection",
        "owasp": "A03:2021 - Injection",
        "explanation": ("User input is concatenated into SQL queries, letting an attacker "
                        "alter query logic to read or modify data."),
        "steps": [
            "Use parameterized queries / prepared statements for all database access.",
            "Validate and allow-list input; apply least-privilege DB accounts.",
            "Use an ORM or query builder that parameterizes by default.",
        ],
        "snippet": ("# python — parameterized query (no string concatenation)\n"
                    "cur.execute(\"SELECT * FROM users WHERE email = ?\", (email,))"),
    },
    "zone_transfer": {
        "match": ["zone transfer", "axfr"],
        "title": "DNS zone transfer exposed",
        "cwe": "CWE-200: Exposure of Sensitive Information",
        "owasp": "A05:2021 - Security Misconfiguration",
        "explanation": ("The name server allows unrestricted AXFR zone transfers, leaking "
                        "the full DNS map of the domain."),
        "steps": [
            "Restrict zone transfers to known secondary name servers only.",
            "Use TSIG keys to authenticate transfers.",
        ],
        "snippet": ("# BIND named.conf — limit transfers\n"
                    "zone \"example.com\" {\n"
                    "    type master;\n"
                    "    allow-transfer { key \"transfer-key\"; };\n"
                    "};"),
    },
    "default_creds": {
        "match": ["default password", "default credential", "weak password",
                  "hardcoded password", "cracked"],
        "title": "Weak or default credentials",
        "cwe": "CWE-1392: Use of Default Credentials",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "explanation": ("Accounts use default, weak or hardcoded credentials that are "
                        "trivially guessed or already public."),
        "steps": [
            "Change all default credentials on first use; forbid known-weak passwords.",
            "Enforce a strong password policy and multi-factor authentication.",
            "Store secrets in a vault, never hardcoded in firmware or source.",
        ],
        "snippet": ("# Enforce MFA + strong policy at the IdP/application layer.\n"
                    "# Never ship default admin/admin; rotate secrets via a secrets manager."),
    },
}

_GENERIC = {
    "title": "Security finding",
    "cwe": "CWE-Unknown (map manually to the closest weakness)",
    "owasp": "A06:2021 - Vulnerable and Outdated Components (verify category)",
    "explanation": ("A potential security issue was identified. Review the finding "
                    "details, confirm exposure, and remediate per vendor guidance."),
    "steps": [
        "Confirm the finding and identify the affected component and version.",
        "Apply the latest vendor patch or upgrade to a supported, fixed version.",
        "Reduce exposure (network controls, least privilege) until patched.",
        "Re-scan to verify the issue is resolved.",
    ],
    "snippet": "# Keep components patched and minimise exposed surface (defence in depth).",
}


def _classify(finding):
    text = " ".join(str(finding.get(k, "")) for k in
                    ("title", "finding_type", "description")).lower()
    for cat in _KB.values():
        if any(kw in text for kw in cat["match"]):
            return cat
    return _GENERIC


def _severity_context(finding):
    """Build a severity line, preferring CVSS data carried on the finding."""
    sev = (finding.get("severity") or "").upper()
    raw = finding.get("raw_data") or {}
    score = finding.get("cvss_score") or raw.get("cvss_score")
    cve_ids = finding.get("cve_ids") or []
    parts = []
    if sev and sev not in ("INFO", "UNKNOWN", ""):
        parts.append(f"Severity: {sev}")
    if score:
        parts.append(f"CVSS: {score}")
    if cve_ids:
        parts.append("CVE: " + ", ".join(cve_ids))
    return " | ".join(parts) if parts else "Severity: informational / unrated"


def generate_remediation(finding_dict, ai_engine=None, use_ai=True):
    """
    Build a structured remediation block for one finding.

    finding_dict keys used (all optional): title, finding_type, description,
    severity, cvss_score, cve_ids, raw_data.

    Returns:
      {
        title, explanation, cwe, owasp, severity_context,
        remediation_steps: [...], secure_snippet, cve_ids: [...],
        exploit_reference: "<str or ''>", ai_explanation: "<str or ''>", source
      }
    """
    finding_dict = finding_dict or {}
    cat = _classify(finding_dict)

    block = {
        "title": finding_dict.get("title") or cat["title"],
        "explanation": cat["explanation"],
        "cwe": cat["cwe"],
        "owasp": cat["owasp"],
        "severity_context": _severity_context(finding_dict),
        "remediation_steps": list(cat["steps"]),
        "secure_snippet": cat["snippet"],
        "cve_ids": finding_dict.get("cve_ids") or [],
        "exploit_reference": "",
        "ai_explanation": "",
        "source": "rule-based",
    }

    # Phase 3 cross-reference: note any known public exploit reference (informational).
    try:
        from modules.intel.exploit_refs import format_ref_line
        for cve in block["cve_ids"]:
            line = format_ref_line(cve)
            if line:
                block["exploit_reference"] = line
                break
    except Exception:
        pass

    # Optional AI enrichment (constrained, defensive). Never required.
    if use_ai:
        try:
            if ai_engine is None:
                from modules.ai.ai_engine import get_active_ai_engine
                ai_engine = get_active_ai_engine()
            prompt = (
                "Provide a defensive remediation explanation for this single finding. "
                "Follow the strict rules in your instructions (no exploit code, no "
                "host-specific patch).\n\n"
                f"Finding title: {block['title']}\n"
                f"Type: {finding_dict.get('finding_type', 'N/A')}\n"
                f"{block['severity_context']}\n"
                f"Details: {str(finding_dict.get('description', ''))[:500]}\n"
            )
            ai_text = ai_engine.analyze(prompt, system_prompt=REMEDIATION_SYSTEM_PROMPT,
                                        show_output=False)
            if ai_text and "[Local fallback]" not in ai_text:
                block["ai_explanation"] = ai_text.strip()
                block["source"] = "ai+rule-based"
        except Exception:
            pass  # AI is best-effort; the rule-based block always stands on its own

    return block


def generate_remediation_for_text(text, ai_engine=None, use_ai=True):
    """Standalone helper: build a finding dict from a pasted finding/CVE string."""
    text = (text or "").strip()
    cve_ids = []
    try:
        from modules.intel.nvd_lookup import extract_cve_ids, lookup_cve
        cve_ids = extract_cve_ids(text)
    except Exception:
        pass

    finding = {"title": text[:80] or "Pasted finding", "finding_type": "manual",
               "description": text, "cve_ids": cve_ids}

    # Enrich severity from NVD if a CVE was pasted.
    if cve_ids:
        try:
            from modules.intel.nvd_lookup import lookup_cve
            info = lookup_cve(cve_ids[0])
            if info:
                finding["severity"] = info.get("severity", "")
                finding["cvss_score"] = info.get("cvss_score")
                if info.get("description") and info["description"] != "Not found in NVD":
                    finding["description"] = info["description"]
        except Exception:
            pass

    return generate_remediation(finding, ai_engine=ai_engine, use_ai=use_ai)


def render_block(block, console=None):
    """Pretty-print a remediation block to the terminal (rich)."""
    from rich.console import Console
    from rich.panel import Panel
    console = console or Console()

    lines = []
    lines.append(f"[bold]Issue:[/bold] {block['title']}")
    lines.append(f"[bold]Severity:[/bold] {block['severity_context']}")
    lines.append(f"[bold]CWE:[/bold] {block['cwe']}")
    lines.append(f"[bold]OWASP:[/bold] {block['owasp']}")
    lines.append("")
    lines.append(f"[bold cyan]Explanation[/bold cyan]\n{block['explanation']}")
    if block.get("ai_explanation"):
        lines.append(f"\n[bold cyan]AI analysis[/bold cyan]\n{block['ai_explanation']}")
    lines.append("\n[bold cyan]Remediation steps[/bold cyan]")
    for i, s in enumerate(block["remediation_steps"], 1):
        lines.append(f"  {i}. {s}")
    lines.append("\n[bold cyan]Secure pattern (generic)[/bold cyan]")
    lines.append(f"[green]{block['secure_snippet']}[/green]")
    if block.get("exploit_reference"):
        lines.append(f"\n[yellow]{block['exploit_reference']}[/yellow]")

    console.print(Panel("\n".join(lines),
                        title="[bold green]🛡  Guided Remediation[/bold green]",
                        border_style="green"))


if __name__ == "__main__":
    demo = {"title": "TLS 1.0 supported (weak — upgrade)",
            "finding_type": "ssl_audit", "severity": "MEDIUM",
            "description": "Server negotiates TLS 1.0 with RC4 cipher."}
    block = generate_remediation(demo, use_ai=False)
    render_block(block)
