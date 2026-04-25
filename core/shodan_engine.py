"""
SenfoniScan - Shodan Intelligence Module
Queries Shodan for open ports, CVEs, banners without touching the target.
"""
import requests
from rich.console import Console

console = Console()


def query_shodan(ip_addresses: list, api_key: str, lang: str = 'en') -> dict:
    """Query Shodan for each IP and return combined results."""
    t = lambda en, tr: tr if lang == 'tr' else en
    if not api_key:
        return {"error": t("API key not provided", "API anahtarı sağlanmadı"), "hosts": []}

    results = {"hosts": [], "error": None}
    for ip in ip_addresses[:5]:  # limit to 5 IPs
        try:
            resp = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}?key={api_key}",
                timeout=15
            )
            if resp.status_code == 200:
                data = resp.json()
                host_info = {
                    "ip": ip,
                    "org": data.get("org", "Unknown"),
                    "os": data.get("os", "Unknown"),
                    "country": data.get("country_name", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "ports": data.get("ports", []),
                    "vulns": list(data.get("vulns", {}).keys()),
                    "hostnames": data.get("hostnames", []),
                    "services": []
                }
                # Extract service banners
                for item in data.get("data", [])[:10]:
                    svc = {
                        "port": item.get("port"),
                        "transport": item.get("transport", "tcp"),
                        "product": item.get("product", ""),
                        "version": item.get("version", ""),
                        "banner": item.get("data", "")[:200].strip()
                    }
                    host_info["services"].append(svc)
                results["hosts"].append(host_info)
                
                port_text = t(f"open ports", f"açık port")
                console.print(
                    f"  [green]  ✔[/green] {ip} → "
                    f"[cyan]{len(host_info['ports'])} {port_text}[/cyan], "
                    f"[{'red' if host_info['vulns'] else 'dim'}]"
                    f"{len(host_info['vulns'])} CVE[/]"
                )
            elif resp.status_code == 404:
                console.print(t(f"  [dim]  - {ip} → No records found in Shodan[/dim]",
                                f"  [dim]  - {ip} → Shodan'da kayıt bulunamadı[/dim]"))
            elif resp.status_code == 401:
                results["error"] = t("Invalid Shodan API key", "Geçersiz Shodan API anahtarı")
                break
        except Exception as e:
            console.print(t(f"  [yellow]  [!] Shodan error ({ip}): {e}[/yellow]",
                            f"  [yellow]  [!] Shodan hatası ({ip}): {e}[/yellow]"))

    return results


def format_shodan_section_md(shodan_data: dict, lang: str) -> str:
    """Format Shodan data as markdown."""
    t = lambda en, tr: tr if lang == 'tr' else en
    
    if shodan_data.get("error"):
        return t(f"> ⚠ Shodan Error: {shodan_data['error']}\n",
                 f"> ⚠ Shodan Hatası: {shodan_data['error']}\n")

    lines = []
    for host in shodan_data.get("hosts", []):
        lines.append(f"### {host['ip']} — {host.get('org', '?')}")
        lines.append(t(f"- **ISP:** {host.get('isp', '?')}", f"- **ISP:** {host.get('isp', '?')}"))
        lines.append(t(f"- **Location:** {host.get('city', '?')}, {host.get('country', '?')}",
                       f"- **Konum:** {host.get('city', '?')}, {host.get('country', '?')}"))
        lines.append(f"- **OS:** {host.get('os', 'Unknown')}")
        if host.get("ports"):
            lines.append(t(f"- **Open Ports:** `{'`, `'.join(str(p) for p in host['ports'])}`",
                           f"- **Açık Portlar:** `{'`, `'.join(str(p) for p in host['ports'])}`"))
        if host.get("vulns"):
            lines.append(f"- **⚠ CVE's:** `{'`, `'.join(host['vulns'])}`" if lang == 'en' else f"- **⚠ CVE'ler:** `{'`, `'.join(host['vulns'])}`")
        lines.append("")
        if host.get("services"):
            lines.append(t("**Services:**", "**Servisler:**"))
            lines.append(t("| Port | Protocol | Product | Version |", "| Port | Protokol | Ürün | Versiyon |"))
            lines.append("|------|----------|------|---------|")
            for svc in host["services"]:
                lines.append(
                    f"| {svc['port']} | {svc['transport']} | "
                    f"{svc.get('product') or '-'} | {svc.get('version') or '-'} |"
                )
        lines.append("")
    return "\n".join(lines) if lines else t("No Shodan data found.", "Shodan verisi bulunamadı.")
