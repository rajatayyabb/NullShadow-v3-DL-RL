import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import socket
import threading
import requests
try:
    import nmap
except ImportError:
    nmap = None
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from config.config import SUBDOMAIN_WORDLIST, VIRUSTOTAL_API_KEY, SHODAN_API_KEY, ABUSEIPDB_API_KEY

console = Console()


class ReconPipeline:

    def __init__(self):
        self.results = {}

    def run_full_recon(self, target):
        self.results = {"target": target, "timestamp": datetime.now().isoformat()}

        console.print(Panel(
            f"[bold red]🚀 AUTONOMOUS RECON STARTED[/bold red]\n[cyan]Target: {target}[/cyan]",
            border_style="red"
        ))

        phases = [
            ("🔍 WHOIS Lookup",      self._whois,      target),
            ("🌐 Subdomain Enum",    self._subdomains,  target),
            ("🔌 Port Scan",         self._port_scan,   target),
            ("💀 Vulnerability Scan",self._vuln_scan,   target),
            ("📍 IP Geolocation",    self._geoip,       target),
            ("🛡️  Threat Intel",     self._threat_intel,target),
            ("🔒 SSL/TLS Audit",     self._ssl_audit,   target),
        ]

        for phase_name, func, arg in phases:
            with Progress(SpinnerColumn(), TextColumn(f"[cyan]{phase_name}..."), transient=True) as p:
                p.add_task("", total=None)
                try:
                    result = func(arg)
                    self.results[phase_name] = result
                    console.print(f"[green]✓[/green] {phase_name} complete")
                except Exception as e:
                    self.results[phase_name] = {"error": str(e)}
                    console.print(f"[red]✗[/red] {phase_name} failed: {str(e)[:60]}")

        return self.results

    # ── WHOIS via RDAP (no port 43 timeout) ───────────────────
    def _whois(self, target):
        # Strip www
        domain = target.replace("www.", "").strip()

        # Method 1: RDAP
        tld = domain.split('.')[-1].lower()
        rdap_servers = {
            'com': f'https://rdap.verisign.com/com/v1/domain/{domain}',
            'net': f'https://rdap.verisign.com/net/v1/domain/{domain}',
            'org': f'https://rdap.publicinterestregistry.org/rdap/domain/{domain}',
            'io':  f'https://rdap.nic.io/domain/{domain}',
        }
        urls = list(rdap_servers.values()) if tld in rdap_servers else []
        urls.append(f"https://rdap.org/domain/{domain}")

        for url in urls:
            try:
                r = requests.get(url, timeout=8, headers={"Accept": "application/json"})
                if r.status_code == 200:
                    d = r.json()
                    result = {"domain": d.get("ldhName", domain), "status": ", ".join(d.get("status", []))}
                    for event in d.get("events", []):
                        action = event.get("eventAction", "")
                        date = event.get("eventDate", "")[:10]
                        if "registration" in action: result["created"] = date
                        elif "expiration" in action: result["expires"] = date
                    for entity in d.get("entities", []):
                        roles = entity.get("roles", [])
                        vcard = entity.get("vcardArray", [None, []])[1]
                        name = next((v[-1] for v in vcard if v[0] == "fn"), None) if vcard else None
                        if "registrar" in roles and name: result["registrar"] = name
                    ns = [ns.get("ldhName","") for ns in d.get("nameservers", [])]
                    if ns: result["nameservers"] = ", ".join(ns)
                    return result
            except Exception:
                continue

        # Method 2: python-whois library
        try:
            import whois as _w
            if hasattr(_w, 'whois'):
                w = _w.whois(domain)
                return {
                    "registrar": str(w.registrar or "N/A"),
                    "created":   str(w.creation_date or "N/A"),
                    "expires":   str(w.expiration_date or "N/A"),
                    "org":       str(w.org or "N/A"),
                }
        except Exception:
            pass

        return {"error": "WHOIS unavailable", "note": "Try: whois " + domain}

    # ── Subdomain Enumeration ─────────────────────────────────
    def _subdomains(self, target):
        domain = target.replace("www.", "").strip()
        found = []
        lock = threading.Lock()

        def check(sub):
            hostname = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(hostname)
                with lock:
                    found.append({"subdomain": hostname, "ip": ip})
            except:
                pass

        threads = []
        for word in SUBDOMAIN_WORDLIST:
            t = threading.Thread(target=check, args=(word,))
            threads.append(t)
            t.start()
            if len(threads) >= 50:
                for t in threads: t.join()
                threads = []
        for t in threads: t.join()
        return {"found": found, "count": len(found)}

    # ── Port Scan ─────────────────────────────────────────────
    def _port_scan(self, target):
        try:
            nm = nmap.PortScanner()
            nm.scan(target, '21-25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,9200,27017', '-T4 -sV')
            ports = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto]:
                        info = nm[host][proto][port]
                        if info['state'] == 'open':
                            ports.append({
                                "port":    port,
                                "service": info.get('name',''),
                                "version": info.get('version',''),
                                "product": info.get('product',''),
                            })
            return {"open_ports": ports, "count": len(ports)}
        except Exception as e:
            return {"error": str(e), "open_ports": [], "count": 0}

    # ── Vulnerability Scan ────────────────────────────────────
    def _vuln_scan(self, target):
        try:
            nm = nmap.PortScanner()
            # Use safe scripts only, skip ones that cause errors
            nm.scan(target, arguments='-sV --script=http-vuln-cve2014-3704,http-shellshock,ssl-heartbleed,smb-vuln-ms17-010 -T4 --top-ports 10')
            vulns = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto]:
                        scripts = nm[host][proto][port].get('script', {})
                        for script_name, output in scripts.items():
                            if any(kw in output.lower() for kw in ['vuln','cve','exploit','vulnerable','state: vulnerable']):
                                vulns.append({
                                    "port":    port,
                                    "script":  script_name,
                                    "finding": output[:200]
                                })
            return {"vulnerabilities": vulns, "count": len(vulns)}
        except Exception as e:
            return {"vulnerabilities": [], "count": 0, "error": str(e)}

    # ── IP Geolocation ────────────────────────────────────────
    def _geoip(self, target):
        try:
            try:
                ip = socket.gethostbyname(target)
            except:
                ip = target
            for api in [f"http://ip-api.com/json/{ip}", f"https://ipinfo.io/{ip}/json", f"https://ipwhois.app/json/{ip}"]:
                try:
                    r = requests.get(api, timeout=6)
                    if r.status_code == 200:
                        return r.json()
                except:
                    continue
            return {"error": "All geolocation APIs failed"}
        except Exception as e:
            return {"error": str(e)}

    # ── Threat Intel ──────────────────────────────────────────
    def _threat_intel(self, target):
        results = {}
        try:
            ip = socket.gethostbyname(target)
        except:
            ip = target

        if VIRUSTOTAL_API_KEY:
            try:
                r = requests.get(
                    f"https://www.virustotal.com/api/v3/domains/{target}",
                    headers={"x-apikey": VIRUSTOTAL_API_KEY}, timeout=10
                )
                if r.status_code == 200:
                    stats = r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
                    results["virustotal"] = stats
                else:
                    results["virustotal"] = f"HTTP {r.status_code}"
            except Exception as e:
                results["virustotal"] = str(e)
        else:
            results["virustotal"] = "No API key"

        if ABUSEIPDB_API_KEY:
            try:
                r = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=10
                )
                if r.status_code == 200:
                    d = r.json().get("data", {})
                    results["abuseipdb"] = {
                        "abuse_score": d.get("abuseConfidenceScore"),
                        "total_reports": d.get("totalReports"),
                    }
            except Exception as e:
                results["abuseipdb"] = str(e)
        else:
            results["abuseipdb"] = "No API key"

        if SHODAN_API_KEY:
            try:
                r = requests.get(
                    f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}", timeout=10
                )
                if r.status_code == 200:
                    d = r.json()
                    results["shodan"] = {"ports": d.get("ports",[]), "vulns": d.get("vulns",[])}
            except Exception as e:
                results["shodan"] = str(e)
        else:
            results["shodan"] = "No API key"

        return results

    # ── SSL/TLS Audit ─────────────────────────────────────────
    def _ssl_audit(self, target):
        import ssl
        domain = target.replace("www.", "").strip()
        try:
            ctx = ssl.create_default_context()
            sock = socket.create_connection((domain, 443), timeout=8)
            conn = ctx.wrap_socket(sock, server_hostname=domain)
            cert = conn.getpeercert()
            cipher = conn.cipher()
            version = conn.version()
            conn.close()

            issuer  = dict(x[0] for x in cert.get("issuer", []))
            subject = dict(x[0] for x in cert.get("subject", []))
            return {
                "tls_version": version,
                "cipher":      cipher[0] if cipher else "N/A",
                "issuer":      issuer.get("organizationName", "N/A"),
                "common_name": subject.get("commonName", "N/A"),
                "expires":     cert.get("notAfter", "N/A"),
            }
        except ssl.SSLError as e:
            return {"error": f"SSL Error: {e}", "tls_version": "Unknown"}
        except socket.timeout:
            return {"error": "SSL connection timed out (port 443 may be closed)"}
        except ConnectionRefusedError:
            return {"error": "Port 443 closed — no HTTPS on this target"}
        except Exception as e:
            return {"error": str(e)}

    # ── Display Summary ───────────────────────────────────────
    def display_summary(self):
        table = Table(title="[bold red]RECON SUMMARY[/bold red]", header_style="bold cyan")
        table.add_column("Phase", style="cyan", width=25)
        table.add_column("Findings", style="white")

        for phase, data in self.results.items():
            if phase in ("target", "timestamp"):
                continue
            if isinstance(data, dict):
                if data.get("error") and not any(k in data for k in ("open_ports","found","vulnerabilities")):
                    val = f"[yellow]{data['error'][:70]}[/yellow]"
                elif "count" in data:
                    color = "green" if data["count"] > 0 else "dim"
                    val = f"[{color}]{data['count']} items found[/{color}]"
                else:
                    items = [(k, str(v)[:50]) for k, v in data.items() if k != "error"][:3]
                    val = ", ".join(f"{k}: {v}" for k, v in items)
            else:
                val = str(data)[:80]
            table.add_row(phase, val)

        console.print(table)

    def format_for_ai(self):
        import json
        return json.dumps(self.results, indent=2, default=str)
