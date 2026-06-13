import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import requests
import socket
import threading

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier
except ImportError:
    phonenumbers = None
    geocoder = None
    carrier = None
from rich.table import Table
from rich.console import Console

console = Console()

PLATFORMS = [
    ("GitHub",      "https://github.com/{}"),
    ("Twitter/X",   "https://twitter.com/{}"),
    ("Instagram",   "https://www.instagram.com/{}"),
    ("Reddit",      "https://www.reddit.com/user/{}"),
    ("TikTok",      "https://www.tiktok.com/@{}"),
    ("LinkedIn",    "https://www.linkedin.com/in/{}"),
    ("Pinterest",   "https://www.pinterest.com/{}"),
    ("YouTube",     "https://www.youtube.com/@{}"),
    ("Twitch",      "https://www.twitch.tv/{}"),
    ("Medium",      "https://medium.com/@{}"),
    ("Dev.to",      "https://dev.to/{}"),
    ("Keybase",     "https://keybase.io/{}"),
    ("Replit",      "https://replit.com/@{}"),
    ("HackerNews",  "https://news.ycombinator.com/user?id={}"),
    ("ProductHunt", "https://www.producthunt.com/@{}"),
    ("GitLab",      "https://gitlab.com/{}"),
    ("Pastebin",    "https://pastebin.com/u/{}"),
    ("Steam",       "https://steamcommunity.com/id/{}"),
]

IP_APIS = [
    "http://ip-api.com/json/{}",
    "https://ipinfo.io/{}/json",
    "https://ipwhois.app/json/{}",
    "https://freeipapi.com/api/json/{}",
    "https://api.country.is/{}",
]


class OSINTModules:

    def domain_whois(self, domain):
        table = Table(title=f"WHOIS: {domain}", header_style="bold yellow")
        table.add_column("Field", style="cyan", width=20)
        table.add_column("Value", style="white")

        # Method 1: RDAP (modern WHOIS replacement, no timeout issues)
        rdap_data = self._rdap_lookup(domain)
        if rdap_data:
            for k, v in rdap_data.items():
                table.add_row(k, str(v)[:120])
            return table

        # Method 2: python-whois library fallback
        try:
            import whois as _whois
            # Try whois.whois() - python-whois package
            if hasattr(_whois, 'whois'):
                w = _whois.whois(domain)
            # Try whois.query() - whois package
            elif hasattr(_whois, 'query'):
                w = _whois.query(domain)
                if w:
                    w = {
                        'Domain Name':  getattr(w, 'name', 'N/A'),
                        'Registrar':    getattr(w, 'registrar', 'N/A'),
                        'Created':      str(getattr(w, 'creation_date', 'N/A')),
                        'Expires':      str(getattr(w, 'expiration_date', 'N/A')),
                        'Name Servers': str(getattr(w, 'name_servers', 'N/A')),
                    }
                    for k, v in w.items():
                        table.add_row(k, str(v)[:120])
                    return table
            else:
                raise Exception("No compatible whois method found")

            fields = {
                "Domain Name":  w.domain_name,
                "Registrar":    w.registrar,
                "Created":      str(w.creation_date),
                "Expires":      str(w.expiration_date),
                "Updated":      str(w.updated_date),
                "Status":       w.status,
                "Name Servers": w.name_servers,
                "Emails":       w.emails,
                "Country":      w.country,
                "Organization": w.org,
            }
            for k, v in fields.items():
                val = ", ".join(v) if isinstance(v, list) else str(v) if v else "N/A"
                table.add_row(k, val[:120])

        except Exception as e:
            err = str(e)
            if "timed out" in err or "connect" in err.lower() or "stdbuf" in err:
                table.add_row("Status", "[yellow]WHOIS timed out. Trying RDAP...[/yellow]")
                # Try RDAP as final fallback
                rdap = self._rdap_lookup(domain)
                if rdap:
                    for k, v in rdap.items():
                        table.add_row(k, str(v)[:120])
                else:
                    table.add_row("Result", "[red]All WHOIS methods failed. Try: whois " + domain + " in terminal[/red]")
            else:
                table.add_row("Error", err[:100])
        return table

    def _rdap_lookup(self, domain):
        """RDAP - modern replacement for WHOIS, uses HTTPS, no port 43 timeouts"""
        tld = domain.split('.')[-1].lower()
        rdap_servers = {
            'com': 'https://rdap.verisign.com/com/v1/domain/',
            'net': 'https://rdap.verisign.com/net/v1/domain/',
            'org': 'https://rdap.publicinterestregistry.org/rdap/domain/',
            'io':  'https://rdap.nic.io/domain/',
            'co':  'https://rdap.nic.co/domain/',
            'uk':  'https://rdap.nominet.uk/uk/domain/',
        }
        urls = []
        if tld in rdap_servers:
            urls.append(rdap_servers[tld] + domain)
        urls.append(f"https://rdap.org/domain/{domain}")

        for url in urls:
            try:
                r = requests.get(url, timeout=8,
                                 headers={"Accept": "application/json"})
                if r.status_code == 200:
                    d = r.json()
                    result = {}
                    result["Domain Name"] = d.get("ldhName", domain).upper()
                    result["Status"] = ", ".join(d.get("status", []))
                    for event in d.get("events", []):
                        action = event.get("eventAction", "")
                        date = event.get("eventDate", "")[:10]
                        if "registration" in action:
                            result["Created"] = date
                        elif "expiration" in action:
                            result["Expires"] = date
                        elif "last changed" in action:
                            result["Updated"] = date
                    for entity in d.get("entities", []):
                        roles = entity.get("roles", [])
                        vcard = entity.get("vcardArray", [None, []])[1]
                        name = next((v[-1] for v in vcard if v[0] == "fn"), None) if vcard else None
                        if "registrar" in roles and name:
                            result["Registrar"] = name
                        if "registrant" in roles and name:
                            result["Registrant"] = name
                    ns_list = [ns.get("ldhName","") for ns in d.get("nameservers", [])]
                    if ns_list:
                        result["Name Servers"] = ", ".join(ns_list)
                    return result
            except Exception:
                continue
        return None

    def username_tracker(self, username):
        table = Table(title=f"Username Tracker: {username}", header_style="bold yellow")
        table.add_column("Platform", style="cyan", width=14)
        table.add_column("URL", style="white")
        table.add_column("Status", style="green", width=12)

        results = []
        lock = threading.Lock()
        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}

        def check(platform, url_template):
            url = url_template.format(username)
            try:
                r = requests.get(url, headers=headers, timeout=6, allow_redirects=True)
                if r.status_code == 200:
                    status = "[green]Found[/green]"
                elif r.status_code == 404:
                    status = "[red]Not Found[/red]"
                else:
                    status = f"[yellow]HTTP {r.status_code}[/yellow]"
            except requests.exceptions.Timeout:
                status = "[dim]Timeout[/dim]"
            except Exception:
                status = "[red]Error[/red]"
            with lock:
                results.append((platform, url, status))

        threads = [threading.Thread(target=check, args=(p, u)) for p, u in PLATFORMS]
        for t in threads: t.start()
        for t in threads: t.join()
        for platform, url, status in sorted(results):
            table.add_row(platform, url, status)
        return table

    def ip_lookup(self, ip):
        table = Table(title=f"IP Lookup: {ip}", header_style="bold yellow")
        table.add_column("Field", style="cyan", width=18)
        table.add_column("Value", style="white")

        data = None
        for api_template in IP_APIS:
            try:
                r = requests.get(api_template.format(ip), timeout=6)
                if r.status_code == 200:
                    data = r.json()
                    if data and "ip" not in str(data).lower() and "country" not in str(data).lower():
                        continue
                    break
            except Exception:
                continue

        if data:
            skip = {"status", "query", "ip"}
            for key, val in data.items():
                if key not in skip and val:
                    table.add_row(str(key).replace("_"," ").title(), str(val))
            try:
                table.add_row("IP", ip)
            except:
                pass
        else:
            table.add_row("Status", "[yellow]Could not reach IP API. Check internet.[/yellow]")
        return table

    def phone_lookup(self, number):
        table = Table(title=f"Phone Lookup: {number}", header_style="bold yellow")
        table.add_column("Field", style="cyan", width=22)
        table.add_column("Value", style="white")
        if not phonenumbers:
            table.add_row("Error", "[red]phonenumbers package not installed.[/red] Install it with `pip install phonenumbers`.")
            return table

        try:
            parsed = phonenumbers.parse(number, None)
            num_type_map = {
                0: "Fixed Line", 1: "Mobile", 2: "Fixed/Mobile",
                3: "Toll Free", 4: "Premium Rate", 6: "VOIP",
                7: "Personal Number", 10: "UAN", 99: "Unknown"
            }
            num_type = phonenumbers.number_type(parsed)
            table.add_row("Valid",                str(phonenumbers.is_valid_number(parsed)))
            table.add_row("Country",              geocoder.description_for_number(parsed, "en") if geocoder else "N/A")
            table.add_row("Carrier",              carrier.name_for_number(parsed, "en") if carrier else "N/A")
            table.add_row("Number Type",          num_type_map.get(num_type, str(num_type)))
            table.add_row("E.164 Format",         phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164))
            table.add_row("International Format", phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL))
            table.add_row("National Format",      phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL))
            table.add_row("Country Code",         str(parsed.country_code))
        except Exception as e:
            table.add_row("Error", f"[red]{e}[/red]\n[yellow]Use format: +923001234567[/yellow]")
        return table
