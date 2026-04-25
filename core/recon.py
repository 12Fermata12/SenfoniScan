"""
SenfoniScan - Parallel Passive Recon Engine (Async)
Uses: crt.sh, dnspython, aiohttp (async), wayback CDX API, cloud bucket probing
"""
import asyncio
import aiohttp
import dns.resolver
import requests
import socket
import re
from rich.console import Console
from datetime import datetime

console = Console()
CONCURRENT_LIMIT = 40  # max parallel HTTP checks


def get_dns_records(domain: str) -> dict:
    """Query all major DNS record types (synchronous, fast)."""
    records = {}
    for rtype in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']:
        try:
            records[rtype] = [str(r) for r in dns.resolver.resolve(domain, rtype)]
        except Exception:
            records[rtype] = []
    return records


def get_ip(domain: str) -> list:
    try:
        return [str(r) for r in dns.resolver.resolve(domain, 'A')]
    except Exception:
        return []


def get_subdomains_passive(domain: str) -> list:
    """Enumerate subdomains using multiple APIs (Hackertarget, AlienVault, crt.sh fallback)."""
    subs = set()
    
    # 1. HackerTarget
    try:
        resp = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=10)
        if resp.status_code == 200:
            for line in resp.text.split('\n'):
                if ',' in line:
                    sub = line.split(',')[0].strip()
                    if domain in sub:
                        subs.add(sub)
        if subs:
            console.print("  [dim]    → HackerTarget database used.[/dim]")
            return sorted(list(subs))
    except Exception:
        pass

    # 2. AlienVault OTX
    try:
        resp = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data.get('passive_dns', []):
                sub = entry.get('hostname', '')
                if domain in sub:
                    subs.add(sub)
        if subs:
            console.print("  [dim]    → AlienVault OTX used.[/dim]")
            return sorted(list(subs))
    except Exception:
        pass

    console.print("  [dim]    HackerTarget and AlienVault did not respond, trying crt.sh...[/dim]")
    for attempt in range(2):
        timeout = 15 + (attempt * 10)
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=timeout,
                headers={"User-Agent": "SenfoniScan/2.0"}
            )
            if resp.status_code == 200:
                for entry in resp.json():
                    for line in entry.get('name_value', '').split('\n'):
                        line = line.strip().lstrip('*.')
                        if domain in line and line != domain:
                            subs.add(line)
                return sorted(list(subs))
        except Exception:
            import time; time.sleep(1)
            
    return []


def _extract_title(html: str) -> str:
    try:
        m = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return m.group(1).strip()[:120] if m else ""
    except Exception:
        return ""


async def _check_single(session: aiohttp.ClientSession, semaphore: asyncio.Semaphore,
                        subdomain: str) -> dict:
    """Async check if a single subdomain is alive."""
    result = {
        "host": subdomain, "alive": False, "http_status": None,
        "https": False, "url": None, "title": "", "server": "Unknown",
        "x_powered_by": ""
    }
    headers = {"User-Agent": "Mozilla/5.0 (SenfoniScan/1.0)"}
    async with semaphore:
        for scheme in ["https", "http"]:
            try:
                url = f"{scheme}://{subdomain}"
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=7),
                                       allow_redirects=True, ssl=False) as resp:
                    html = await resp.text(errors='ignore')
                    result.update({
                        "alive": True,
                        "http_status": resp.status,
                        "https": (scheme == "https"),
                        "url": str(resp.url),
                        "title": _extract_title(html),
                        "server": resp.headers.get("Server", "Unknown"),
                        "x_powered_by": resp.headers.get("X-Powered-By", ""),
                    })
                    break
            except Exception:
                continue
    return result


async def _check_all_subdomains(subdomains: list, max_check: int = 60) -> list:
    """Check all subdomains in parallel using aiohttp + semaphore."""
    semaphore = asyncio.Semaphore(CONCURRENT_LIMIT)
    connector = aiohttp.TCPConnector(ssl=False, limit=CONCURRENT_LIMIT)
    results = []
    targets = subdomains[:max_check]
    completed = 0

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [_check_single(session, semaphore, sub) for sub in targets]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            completed += 1
            icon = "✔" if result["alive"] else "✘"
            color = "green" if result["alive"] else "red"
            http_info = f"HTTP {result['http_status']}" if result["alive"] else "Unreachable"
            console.print(
                f"    [{color}][{icon}][/{color}] "
                f"[white]{result['host']}[/white] [dim]→ {http_info}[/dim] "
                f"[dim]({completed}/{len(targets)})[/dim]"
            )
            results.append(result)
    return results


def get_wayback_urls(domain: str, limit: int = 25) -> list:
    try:
        url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}&output=json&fl=original&collapse=urlkey"
            f"&limit={limit}&filter=statuscode:200"
        )
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            return [row[0] for row in data[1:] if row]
    except Exception as e:
        console.print(f"[yellow]  [!] Wayback error: {e}[/yellow]")
    return []


def check_cloud_buckets(domain: str) -> list:
    base = domain.replace('.', '-').split('-')[0]
    guesses = [
        f"{base}.s3.amazonaws.com",
        f"{base}-backup.s3.amazonaws.com",
        f"{base}-dev.s3.amazonaws.com",
        f"{base}-assets.s3.amazonaws.com",
        f"{base}-prod.s3.amazonaws.com",
        f"{base}-staging.s3.amazonaws.com",
        f"{base}-data.s3.amazonaws.com",
        f"{base}-logs.s3.amazonaws.com",
    ]
    found = []
    for bucket in guesses:
        try:
            resp = requests.get(f"https://{bucket}", timeout=5)
            if resp.status_code in [200, 403]:
                found.append({
                    "bucket": bucket,
                    "status": resp.status_code,
                    "accessible": resp.status_code == 200
                })
        except Exception:
            continue
    return found
    return found


SENSITIVE_EXTENSIONS = [
    ".env", "config.php", "wp-config.php", ".git/config", ".git/", 
    "id_rsa", ".bak", ".sql", ".db", ".sqlite", ".db3", "docker-compose.yml", 
    "swagger.json", ".pem", ".key", "passwd", "shadow", ".log", "backup.zip"
]

def find_secrets(urls: list) -> list:
    secrets = []
    for url in urls:
        lower_url = url.lower()
        for ext in SENSITIVE_EXTENSIONS:
            if ext in lower_url:
                secrets.append({"url": url, "type": ext})
                break
    return secrets

def get_whois_asn(domain: str, ips: list) -> dict:
    data = {"whois": {}, "asn": []}
    try:
        import whois
        w = whois.whois(domain)
        data["whois"] = {
            "registrar": w.get("registrar"),
            "creation_date": str(w.get("creation_date", "Unknown")),
            "emails": w.get("emails", "Unknown")
        }
    except Exception:
        pass
        
    try:
        from ipwhois import IPWhois
        for ip in ips[:2]:
            try:
                obj = IPWhois(ip)
                res = obj.lookup_rdap()
                data["asn"].append({
                    "ip": ip,
                    "asn": res.get("asn"),
                    "asn_description": res.get("asn_description"),
                    "network": res.get("network", {}).get("name")
                })
            except Exception:
                pass
    except ImportError:
        pass
        
    return data


def run_passive_recon(domain: str, is_fast: bool, lang: str = 'en') -> dict:
    """Run full parallel passive recon pipeline."""
    t = lambda en, tr: tr if lang == 'tr' else en

    console.print(t(f"\n  [bold cyan][+] Querying DNS records...[/bold cyan]",
                    f"\n  [bold cyan][+] DNS kayıtları sorgulanıyor...[/bold cyan]"))
    dns_records = get_dns_records(domain)
    ip_addresses = get_ip(domain)

    console.print(t(f"  [bold cyan][+] Querying WHOIS & ASN...[/bold cyan]",
                    f"  [bold cyan][+] WHOIS & ASN sorgulanıyor...[/bold cyan]"))
    whois_asn = get_whois_asn(domain, ip_addresses)
    if whois_asn.get("whois"):
        console.print(t(f"  [green]    → WHOIS data retrieved[/green]",
                        f"  [green]    → WHOIS verisi alındı[/green]"))
    if whois_asn.get("asn"):
        console.print(t(f"  [green]    → Found {len(whois_asn['asn'])} ASN records[/green]",
                        f"  [green]    → {len(whois_asn['asn'])} ASN kaydı bulundu[/green]"))

    console.print(t(f"  [bold cyan][+] Searching for subdomains (HackerTarget/AlienVault/crt.sh)...[/bold cyan]",
                    f"  [bold cyan][+] Subdomainler aranıyor (HackerTarget/AlienVault/crt.sh)...[/bold cyan]"))
    subdomains_raw = get_subdomains_passive(domain)
    console.print(t(f"  [green]    → {len(subdomains_raw)} unique subdomains found[/green]",
                    f"  [green]    → {len(subdomains_raw)} benzersiz subdomain bulundu[/green]"))

    console.print(t(
        f"  [bold cyan][+] Checking alive subdomains in parallel "
        f"[dim]({CONCURRENT_LIMIT} concurrent connections)[/dim]...[/bold cyan]",
        f"  [bold cyan][+] Aktif subdomainler paralel olarak kontrol ediliyor "
        f"[dim]({CONCURRENT_LIMIT} eşzamanlı bağlantı)[/dim]...[/bold cyan]"
    ))
    alive_subdomains = asyncio.run(_check_all_subdomains(subdomains_raw))

    wayback_urls = []
    cloud_buckets = []
    if not is_fast:
        console.print(t(f"  [bold cyan][+] Scanning Wayback Machine archive...[/bold cyan]",
                        f"  [bold cyan][+] Wayback Machine arşivi taranıyor...[/bold cyan]"))
        wayback_urls = get_wayback_urls(domain)
        console.print(t(f"  [green]    → {len(wayback_urls)} archive URLs found[/green]",
                        f"  [green]    → {len(wayback_urls)} arşiv URL'si bulundu[/green]"))

        console.print(t(f"  [bold cyan][+] Hunting for secrets in Wayback URLs...[/bold cyan]",
                        f"  [bold cyan][+] Wayback URL'lerinde sırlar aranıyor...[/bold cyan]"))
        secrets = find_secrets(wayback_urls)
        if secrets:
            console.print(t(f"  [bold red]  ⚠ {len(secrets)} potential secrets found! (.env, config, keys)[/bold red]",
                            f"  [bold red]  ⚠ {len(secrets)} potansiyel sır bulundu! (.env, config, keys)[/bold red]"))
        else:
            console.print(t(f"  [dim]    → No clear secrets found in URLs[/dim]",
                            f"  [dim]    → URL'lerde belirgin bir sır bulunamadı[/dim]"))

        console.print(t(f"  [bold cyan][+] Checking for open cloud buckets...[/bold cyan]",
                        f"  [bold cyan][+] Açık cloud bucket'lar kontrol ediliyor...[/bold cyan]"))
        cloud_buckets = check_cloud_buckets(domain)
        found_open = [b for b in cloud_buckets if b.get("accessible")]
        if found_open:
            console.print(t(f"  [bold red]  ⚠ {len(found_open)} OPEN buckets found![/bold red]",
                            f"  [bold red]  ⚠ {len(found_open)} AÇIK bucket bulundu![/bold red]"))

    return {
        "domain": domain,
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip_addresses": ip_addresses,
        "dns_records": dns_records,
        "whois_asn": whois_asn,
        "subdomains_raw": subdomains_raw,
        "alive_subdomains": alive_subdomains,
        "wayback_urls": wayback_urls,
        "secrets": secrets if not is_fast else [],
        "cloud_buckets": cloud_buckets,
    }
