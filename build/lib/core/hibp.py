"""
SenfoniScan - HaveIBeenPwned (HIBP) Integration
Checks if domain emails have appeared in known data breaches.
Free API endpoint used: /breaches (no key required for domain listing).
Breach account check requires API key.
"""
import requests
import time
from rich.console import Console

console = Console()

HIBP_BASE = "https://haveibeenpwned.com/api/v3"
HEADERS = {
    "User-Agent": "SenfoniScan/1.0",
    "hibp-api-key": ""  # filled at runtime if provided
}


def get_all_breaches() -> list:
    """Fetch complete breach database (no key needed)."""
    try:
        resp = requests.get(f"{HIBP_BASE}/breaches", timeout=15,
                            headers={"User-Agent": "SenfoniScan/1.0"})
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        console.print(f"  [yellow]  [!] HIBP bağlantı hatası: {e}[/yellow]")
    return []


def check_domain_breaches(domain: str) -> list:
    """
    Filter known breaches by domain — no API key required.
    Returns breaches where the breach domain matches target.
    """
    all_breaches = get_all_breaches()
    domain_base = domain.lower().split('.')[0]
    matched = []
    for breach in all_breaches:
        breach_domain = breach.get("Domain", "").lower()
        breach_name = breach.get("Name", "").lower()
        if (domain.lower() in breach_domain or
                domain_base in breach_domain or
                domain_base in breach_name):
            matched.append({
                "name": breach.get("Name"),
                "domain": breach.get("Domain"),
                "breach_date": breach.get("BreachDate"),
                "pwn_count": breach.get("PwnCount", 0),
                "data_classes": breach.get("DataClasses", []),
                "is_verified": breach.get("IsVerified", False),
                "description": breach.get("Description", "")[:300]
            })
    return matched


def check_account_breaches(email: str, api_key: str) -> list:
    """Check specific email against HIBP (requires API key)."""
    if not api_key:
        return []
    try:
        resp = requests.get(
            f"{HIBP_BASE}/breachedaccount/{email}?truncateResponse=false",
            headers={"User-Agent": "SenfoniScan/1.0", "hibp-api-key": api_key},
            timeout=15
        )
        time.sleep(1.6)  # HIBP rate limit: 1 req/1.5s
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            return []  # clean
    except Exception as e:
        console.print(f"  [yellow]    [!] HIBP hesap hatası ({email}): {e}[/yellow]")
    return []


def run_hibp_check(domain: str, emails: list, api_key: str = "", lang: str = "en") -> dict:
    """Run full HIBP check — domain breach database + optional per-email check."""
    t = lambda en, tr: tr if lang == 'tr' else en
    
    console.print(t(f"  [bold cyan][+] Scanning HIBP database...[/bold cyan]",
                    f"  [bold cyan][+] HIBP veri tabanı taranıyor...[/bold cyan]"))
    domain_breaches = check_domain_breaches(domain)

    if domain_breaches:
        console.print(t(
            f"  [bold red]  ⚠ {len(domain_breaches)} related breach records found![/bold red]",
            f"  [bold red]  ⚠ {len(domain_breaches)} ilgili sızıntı kaydı bulundu![/bold red]"
        ))
        for b in domain_breaches:
            console.print(t(
                f"    [red]►[/red] {b['name']} [{b['breach_date']}] "
                f"— [yellow]{b['pwn_count']:,}[/yellow] accounts affected",
                f"    [red]►[/red] {b['name']} [{b['breach_date']}] "
                f"— [yellow]{b['pwn_count']:,}[/yellow] hesap etkilendi"
            ))
    else:
        console.print(t(f"  [green]  ✔ No breach records found for domain in HIBP.[/green]",
                        f"  [green]  ✔ HIBP veri tabanında domain için kayıt bulunamadı.[/green]"))

    account_results = {}
    if api_key and emails:
        console.print(t(f"  [bold cyan][+] Checking individual email breaches...[/bold cyan]",
                        f"  [bold cyan][+] Bireysel e-posta sızıntı kontrolü...[/bold cyan]"))
        for email in emails[:5]:
            breaches = check_account_breaches(email, api_key)
            account_results[email] = breaches
            color = "red" if breaches else "green"
            icon = "⚠" if breaches else "✔"
            status_en = 'Clean' if not breaches else str(len(breaches)) + ' breaches!'
            status_tr = 'Temiz' if not breaches else str(len(breaches)) + ' sızıntı!'
            console.print(
                f"  [{color}]  {icon}[/{color}] {email} → "
                f"{t(status_en, status_tr)}"
            )

    return {
        "domain_breaches": domain_breaches,
        "account_breaches": account_results,
        "api_key_used": bool(api_key)
    }


def extract_emails_from_recon(recon_data: dict) -> list:
    """Extract potential email addresses found during recon."""
    domain = recon_data.get("domain", "")
    emails = []
    # Common admin emails guessed from domain
    for prefix in ["admin", "info", "it", "security", "webmaster", "contact", "support"]:
        emails.append(f"{prefix}@{domain}")
    return emails
