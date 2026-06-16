import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from rich.table import Table
from rich.console import Console
import os

console = Console()

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "banking", "paypal", "signin", "password", "credential", "ebay",
    "amazon", "apple", "microsoft", "google", "facebook", "netflix",
    "validate", "suspend", "unusual", "access", "recover", "unlock"
]

SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
                   ".click", ".pw", ".work", ".party", ".loan", ".review"]


class UtilityModules:

    def url_phishing_analyzer(self, url):
        table = Table(title=f"Phishing Analysis", show_header=True, header_style="bold red")
        table.add_column("Check", style="cyan", width=25)
        table.add_column("Result", style="white")
        table.add_column("Risk", style="red", width=10)

        try:
            if not url.startswith("http"):
                url = "http://" + url
            parsed = urlparse(url)
            domain = parsed.netloc.lower().replace("www.", "")
            full   = url.lower()

            score = 0

            https = parsed.scheme == "https"
            risk_https = "[green]Low[/green]" if https else "[red]High[/red]"
            if not https: score += 2
            table.add_row("HTTPS", "Yes" if https else "No", risk_https)

            found_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full]
            risk_kw = "[green]Low[/green]" if not found_kw else "[yellow]Medium[/yellow]" if len(found_kw) < 3 else "[red]High[/red]"
            if found_kw: score += len(found_kw)
            table.add_row("Suspicious Keywords", ", ".join(found_kw) if found_kw else "None", risk_kw)

            sus_tld = any(domain.endswith(tld.lstrip(".")) for tld in SUSPICIOUS_TLDS)
            if sus_tld: score += 3
            table.add_row("Suspicious TLD", domain.split(".")[-1], "[red]High[/red]" if sus_tld else "[green]Low[/green]")

            ip_domain = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain))
            if ip_domain: score += 4
            table.add_row("IP as Domain", "Yes" if ip_domain else "No", "[red]High[/red]" if ip_domain else "[green]Low[/green]")

            sub_count = domain.count(".")
            if sub_count > 3: score += 2
            table.add_row("Subdomain Depth", str(sub_count), "[red]High[/red]" if sub_count > 3 else "[green]Low[/green]")

            url_len = len(url)
            if url_len > 100: score += 1
            table.add_row("URL Length", f"{url_len} chars", "[yellow]Medium[/yellow]" if url_len > 100 else "[green]Low[/green]")

            specials = url.count("-") + url.count("@") + url.count("%")
            if specials > 3: score += 1
            table.add_row("Special Chars", str(specials), "[yellow]Medium[/yellow]" if specials > 3 else "[green]Low[/green]")

            has_at = "@" in url
            if has_at: score += 3
            table.add_row("@ in URL", "Yes ⚠" if has_at else "No", "[red]Critical[/red]" if has_at else "[green]Low[/green]")

            double_slash = url.count("//") > 1
            if double_slash: score += 2
            table.add_row("Double Slash Redirect", "Yes ⚠" if double_slash else "No", "[red]High[/red]" if double_slash else "[green]Low[/green]")

            if score == 0:
                verdict = "[bold green]✓ LIKELY SAFE[/bold green]"
            elif score <= 3:
                verdict = "[bold yellow]⚠ SUSPICIOUS[/bold yellow]"
            elif score <= 6:
                verdict = "[bold red]✗ LIKELY PHISHING[/bold red]"
            else:
                verdict = "[bold red]✗✗ HIGH CONFIDENCE PHISHING[/bold red]"

            table.add_row("━━━ VERDICT ━━━", verdict, f"Score: {score}/20")

        except Exception as e:
            table.add_row("Error", str(e), "-")
        return table

    def website_cloner(self, url):
        table = Table(title=f"Website Cloner: {url}", show_header=True, header_style="bold green")
        table.add_column("Item", style="cyan", width=18)
        table.add_column("Details", style="white")

        try:
            if not url.startswith("http"):
                url = "http://" + url
            headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
            r = requests.get(url, headers=headers, timeout=10)
            soup = BeautifulSoup(r.text, "html.parser")

            filename = urlparse(url).netloc.replace(".", "_") + ".html"
            filepath = f"/tmp/{filename}"
            with open(filepath, "w", encoding="utf-8", errors="replace") as f:
                f.write(r.text)

            forms = soup.find_all("form")
            inputs = soup.find_all("input")
            scripts = soup.find_all("script")
            links = soup.find_all("a", href=True)
            images = soup.find_all("img")

            table.add_row("Status Code",    f"[green]{r.status_code}[/green]" if r.status_code == 200 else f"[yellow]{r.status_code}[/yellow]")
            table.add_row("Page Title",     soup.title.string.strip() if soup.title and soup.title.string else "N/A")
            table.add_row("Content Size",   f"{len(r.text):,} chars")
            table.add_row("Links Found",    str(len(links)))
            table.add_row("Images Found",   str(len(images)))
            table.add_row("Forms Found",    f"[yellow]{len(forms)}[/yellow]" if forms else "0")
            table.add_row("Input Fields",   f"[yellow]{len(inputs)}[/yellow]" if inputs else "0")
            table.add_row("JS Scripts",     str(len(scripts)))
            table.add_row("Saved To",       f"[green]{filepath}[/green]")

            if forms:
                table.add_row("⚠ Note", "[yellow]Forms detected — possible login/data collection page[/yellow]")

        except requests.exceptions.ConnectionError:
            table.add_row("Error", "[red]Cannot connect. Check URL or internet.[/red]")
        except requests.exceptions.Timeout:
            table.add_row("Error", "[red]Request timed out.[/red]")
        except Exception as e:
            table.add_row("Error", str(e))
        return table

    def cookie_security_auditor(self, url):
        table = Table(title=f"Cookie Audit: {url}", show_header=True, header_style="bold green")
        table.add_column("Cookie Name", style="cyan")
        table.add_column("HttpOnly", style="white", width=10)
        table.add_column("Secure", style="white", width=8)
        table.add_column("SameSite", style="white", width=10)
        table.add_column("Risk", style="red", width=10)

        try:
            if not url.startswith("http"):
                url = "http://" + url
            headers = {"User-Agent": "Mozilla/5.0"}
            r = requests.get(url, headers=headers, timeout=10)

            raw_cookies = r.headers.get("Set-Cookie", "")
            cookies = r.cookies

            if not cookies and not raw_cookies:
                table.add_row("No cookies found", "-", "-", "-", "[green]Low[/green]")
                return table

            for cookie in cookies:
                raw = raw_cookies.lower()
                http_only = "httponly" in raw
                secure    = cookie.secure
                same_site = "None"
                if "samesite=strict" in raw: same_site = "Strict"
                elif "samesite=lax" in raw:  same_site = "Lax"
                elif "samesite=none" in raw:  same_site = "None"
                else:                         same_site = "Not Set"

                risk_score = sum([not http_only, not secure, same_site in ("Not Set", "None")])
                risk = ["[green]Low[/green]", "[yellow]Medium[/yellow]", "[red]High[/red]", "[red]Critical[/red]"][min(risk_score, 3)]

                table.add_row(
                    cookie.name,
                    "[green]✓[/green]" if http_only else "[red]✗[/red]",
                    "[green]✓[/green]" if secure    else "[red]✗[/red]",
                    same_site,
                    risk
                )

        except requests.exceptions.ConnectionError:
            table.add_row("Error", "[red]Cannot connect[/red]", "-", "-", "-")
        except Exception as e:
            table.add_row("Error", str(e)[:60], "-", "-", "-")
        return table
