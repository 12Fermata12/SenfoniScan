import os
import sys
import json
import subprocess
import importlib
import click

def _auto_setup():
    """
    Standalone çalıştırıldığında (pip ile kurulmadan) bağımlılıkları kontrol eder 
    ve gerekirse sanal ortam oluşturup kendini orada yeniden başlatır.
    """
    _SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
    _VENV_DIR     = os.path.join(_SCRIPT_DIR, ".venv")
    _VENV_PYTHON  = os.path.join(_VENV_DIR, "bin", "python")
    _VENV_PIP     = os.path.join(_VENV_DIR, "bin", "pip")
    _VENV_MARKER  = os.path.join(_VENV_DIR, "senfoniscan_ready")

    _ALL_PACKAGES = [
        "click", "rich", "requests", "dnspython", "aiohttp",
        "jinja2", "pydantic", "shodan", "ollama", "playwright", "openai",
        "ipwhois", "python-whois"
    ]

    def _c(code, msg):
        print(f"\033[{code}m{msg}\033[0m")

    # venv kontrolü
    _in_venv = (
        hasattr(sys, "real_prefix") or
        (hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix)
    )

    if not _in_venv:
        # venv yoksa oluştur ve kur
        if not os.path.isdir(_VENV_DIR):
            _c(96, "\n[*] İlk çalıştırma tespit edildi — sanal ortam (.venv) oluşturuluyor...")
            subprocess.run([sys.executable, "-m", "venv", _VENV_DIR], check=True)

        if not os.path.isfile(_VENV_MARKER):
            _c(93, "[*] Bağımlılıklar kuruluyor, lütfen bekleyin...\n")
            subprocess.run([_VENV_PIP, "install", "--quiet", "--upgrade", "pip"], check=False)
            result = subprocess.run([_VENV_PIP, "install"] + _ALL_PACKAGES)
            if result.returncode != 0:
                _c(91, "[!] Pip kurulumu başarısız oldu!")
                sys.exit(1)

            _c(96, "\n[*] Playwright Chromium kuruluyor...")
            subprocess.run([_VENV_PYTHON, "-m", "playwright", "install", "chromium"], check=False)
            open(_VENV_MARKER, "w").close()
            _c(92, "[✔] Tüm bağımlılıklar başarıyla kuruldu!\n")

        # venv ile yeniden başlat
        os.execv(_VENV_PYTHON, [_VENV_PYTHON] + sys.argv)
    else:
        # venv içindeyiz ama eksik paket kontrolü
        _missing = []
        for _pkg_import, _pkg_name in [
            ("dns", "dnspython"), ("shodan", "shodan"),
            ("ollama", "ollama"), ("playwright", "playwright"),
            ("ipwhois", "ipwhois"), ("whois", "python-whois")
        ]:
            try:
                importlib.import_module(_pkg_import)
            except ImportError:
                _missing.append(_pkg_name)
        if _missing:
            subprocess.run([sys.executable, "-m", "pip", "install", "--quiet"] + _missing, check=False)
            importlib.invalidate_caches()
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from core.setup_check import check_playwright_browser, check_ollama
from core.recon import run_passive_recon
from core.screenshotter import screenshot_alive_subdomains
from core.ai_engine import run_ai_analysis
from core.reporter import generate_report
from core.shodan_engine import query_shodan
from core.hibp import run_hibp_check, extract_emails_from_recon

console = Console()

BANNER = r"""
███████╗███████╗███╗   ██╗███████╗ ██████╗ ███╗   ██╗██╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██╔════╝████╗  ██║██╔════╝██╔═══██╗████╗  ██║██║██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗█████╗  ██╔██╗ ██║█████╗  ██║   ██║██╔██╗ ██║██║███████╗██║     ███████║██╔██╗ ██║
╚════██║██╔══╝  ██║╚██╗██║██╔══╝  ██║   ██║██║╚██╗██║██║╚════██║██║     ██╔══██║██║╚██╗██║
███████║███████╗██║ ╚████║██║     ╚██████╔╝██║ ╚████║██║███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═══╝╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝"""


def print_banner():
    console.print(f"[bold red]{BANNER}[/bold red]")
    console.print()
    console.print(
        Panel.fit(
            "[bold cyan]SenfoniScan v2.0[/bold cyan] [dim]|[/dim] "
            "[white]AI-Powered Passive Reconnaissance CLI[/white]\n"
            "[dim]DNS • Subdomain(Async) • Screenshots • Wayback • Cloud • Shodan • HIBP • AI Report[/dim]",
            border_style="dim cyan",
            padding=(0, 2),
        )
    )
    console.print()


def print_summary_table(recon_data: dict, screenshots: dict,
                        shodan_data: dict, hibp_data: dict, lang: str = 'en'):
    alive = [s for s in recon_data.get("alive_subdomains", []) if s["alive"]]
    
    t_title = "📊 Tarama Özeti" if lang == 'tr' else "📊 Scan Summary"
    t_metric = "Metrik" if lang == 'tr' else "Metric"
    t_value = "Değer" if lang == 'tr' else "Value"
    
    table = Table(title=t_title, box=box.ROUNDED, border_style="dim cyan", show_header=True)
    table.add_column(t_metric, style="bold cyan", min_width=30)
    table.add_column(t_value, style="bold white")

    table.add_row("🌐 Domain", recon_data["domain"])
    table.add_row("📅 " + ("Tarama Tarihi" if lang == 'tr' else "Scan Date"), recon_data["scan_date"])
    table.add_row("🔎 " + ("Toplam Subdomain" if lang == 'tr' else "Total Subdomains"), str(len(recon_data.get("subdomains_raw", []))))
    table.add_row("✔ " + ("Aktif Subdomain" if lang == 'tr' else "Alive Subdomains"), f"[green]{len(alive)}[/green]")
    table.add_row("✘ " + ("Ulaşılamayan" if lang == 'tr' else "Unreachable"), f"[red]{len(recon_data.get('alive_subdomains', [])) - len(alive)}[/red]")
    table.add_row("⏳ " + ("Wayback Arşiv URL'leri" if lang == 'tr' else "Wayback Archive URLs"), str(len(recon_data.get("wayback_urls", []))))
    
    secrets = recon_data.get("secrets", [])
    if secrets:
        table.add_row("🔑 " + ("Bulunan Sırlar" if lang == 'tr' else "Secrets Found"), f"[bold red]{len(secrets)} potential[/bold red]")
        
    whois_asn = recon_data.get("whois_asn", {})
    if whois_asn.get("whois") or whois_asn.get("asn"):
        table.add_row("🏢 WHOIS / ASN", "[green]" + ("Toplandı" if lang == 'tr' else "Gathered") + "[/green]")

    cloud_open = [b for b in recon_data.get("cloud_buckets", []) if b.get("accessible")]
    table.add_row("☁ " + ("Açık Bulut Depoları" if lang == 'tr' else "Open Cloud Buckets"),
                  f"[bold red]{len(cloud_open)} OPEN[/bold red]" if cloud_open else "0")

    shodan_hosts = shodan_data.get("hosts", []) if shodan_data else []
    all_vulns = [v for h in shodan_hosts for v in h.get("vulns", [])]
    table.add_row("🔍 Shodan Hosts",
                  f"{len(shodan_hosts)}" if shodan_hosts else "[dim]" + ("Atlandı" if lang == 'tr' else "Skipped") + "[/dim]")
    if all_vulns:
        table.add_row("💀 Shodan CVEs",
                      f"[bold red]{len(all_vulns)} CVEs found![/bold red]")

    domain_breaches = hibp_data.get("domain_breaches", []) if hibp_data else []
    table.add_row("📧 HIBP Breaches",
                  f"[bold red]{len(domain_breaches)} records[/bold red]" if domain_breaches
                  else "[green]Clean[/green]" if hibp_data else "[dim]Skipped[/dim]")

    table.add_row("📷 Screenshots", f"[green]{len(screenshots)}[/green]")

    console.print()
    console.print(table)


CONFIG_FILE = "config.json"

DEFAULT_CONFIG = {
    "language": "en",
    "max_screenshots": 15,
    "fast_mode": False,
    "no_screenshot": False,
    "no_hibp": False,
    "no_ai": False,
    "ai_model": "",
    "api_keys": {
        "shodan": "",
        "hibp": "",
        "openai": "",
        "gemini": "",
        "claude": "",
        "groq": ""
    },
    "webhooks": {
        "discord": ""
    }
}

def load_config():
    if not os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(DEFAULT_CONFIG, f, indent=4)
        except Exception:
            pass
        return DEFAULT_CONFIG
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return DEFAULT_CONFIG


@click.command(name="senfoniscan")
@click.option('--url', '-u', required=True, help='Target domain (e.g., example.com)')
@click.option('--lang', '-l', default=None, type=click.Choice(['tr', 'en'], case_sensitive=False),
              help='Report language (tr/en) [Config default: en]')
@click.option('--fast', '-f', is_flag=True, help='Fast mode — skips Wayback and cloud checks')
@click.option('--no-screenshot', is_flag=True, help='Skip taking screenshots')
@click.option('--max-screenshots', default=None, type=int, help='Maximum number of screenshots [Config default: 15]')
@click.option('--shodan-key', default=None, envvar='SHODAN_API_KEY',
              help='Shodan API key')
@click.option('--hibp-key', default=None, envvar='HIBP_API_KEY',
              help='HaveIBeenPwned API key')
@click.option('--openai-key', default=None, envvar='OPENAI_API_KEY',
              help='OpenAI API key')
@click.option('--gemini-key', default=None, envvar='GEMINI_API_KEY',
              help='Google Gemini API key')
@click.option('--claude-key', default=None, envvar='ANTHROPIC_API_KEY',
              help='Anthropic Claude API key')
@click.option('--groq-key', default=None, envvar='GROQ_API_KEY',
              help='Groq API key (free, fast)')
@click.option('--ai-model', default=None,
              help='AI model (e.g., gpt-4o, gemini-2.5-flash, claude-sonnet-4-20250514, llama3)')
@click.option('--no-hibp', is_flag=True, help='Skip HIBP check')
@click.option('--no-ai', is_flag=True, help='Skip AI analysis entirely')
@click.option('--output', '-o', default=None, help='Output directory (default: Report_<domain>)')
@click.option('--webhook', default=None, help='Discord/Slack webhook URL to send summary')
@click.option('--export-pdf', is_flag=True, help='Also generate a PDF report')
def main(url, lang, fast, no_screenshot, max_screenshots, shodan_key, hibp_key,
         openai_key, gemini_key, claude_key, groq_key, ai_model, no_hibp, no_ai, output, webhook, export_pdf):
    """
    \b
    SenfoniScan v2.0 - AI-Powered Passive Reconnaissance CLI
    ═══════════════════════════════════════════════════════════
    Generates DNS, subdomain, screenshot, Wayback, Shodan,
    HIBP, and AI reports without touching the target.

    \b
    AI Providers (in priority order):
      OpenAI  → --openai-key or $OPENAI_API_KEY
      Gemini  → --gemini-key or $GEMINI_API_KEY
      Claude  → --claude-key or $ANTHROPIC_API_KEY
      Groq    → --groq-key   or $GROQ_API_KEY  (free!)
      Ollama  → Local (no key required)

    \b
    Examples:
      senfoniscan -u target.com
      senfoniscan -u target.com --gemini-key XXXX
      senfoniscan -u target.com --groq-key XXXX --ai-model llama-3.3-70b-versatile
      senfoniscan -u target.com --openai-key XXXX --shodan-key YYYY
    """
    # Auto setup
    check_playwright_browser()
    check_ollama()

    # Load and merge config
    config = load_config()
    lang = lang or config.get("language", "en")
    fast = fast or config.get("fast_mode", False)
    no_screenshot = no_screenshot or config.get("no_screenshot", False)
    max_screenshots = max_screenshots if max_screenshots is not None else config.get("max_screenshots", 15)
    
    api_cfg = config.get("api_keys", {})
    shodan_key = shodan_key or api_cfg.get("shodan")
    hibp_key = hibp_key or api_cfg.get("hibp")
    openai_key = openai_key or api_cfg.get("openai")
    gemini_key = gemini_key or api_cfg.get("gemini")
    claude_key = claude_key or api_cfg.get("claude")
    groq_key = groq_key or api_cfg.get("groq")
    
    ai_model = ai_model or config.get("ai_model")
    no_hibp = no_hibp or config.get("no_hibp", False)
    no_ai = no_ai or config.get("no_ai", False)
    webhook = webhook or config.get("webhooks", {}).get("discord")

    print_banner()

    domain = url.lower().strip().removeprefix("http://").removeprefix("https://").split('/')[0]

    # Detect AI provider
    ai_provider = "Ollama (Local)"
    if openai_key:   ai_provider = "✔ OpenAI"
    elif gemini_key: ai_provider = "✔ Google Gemini"
    elif claude_key: ai_provider = "✔ Anthropic Claude"
    elif groq_key:   ai_provider = "✔ Groq"
    if no_ai:        ai_provider = "✘ Skipped"

    console.print(Panel(
        f"[bold yellow]Target :[/bold yellow] [white]{domain}[/white]\n"
        f"[bold yellow]Lang   :[/bold yellow] [white]{lang.upper()}[/white]\n"
        f"[bold yellow]Mode   :[/bold yellow] [white]{'⚡ Fast' if fast else '🔬 Full'}[/white]\n"
        f"[bold yellow]SS     :[/bold yellow] [white]{'No' if no_screenshot else f'Yes (max {max_screenshots})'}[/white]\n"
        f"[bold yellow]Shodan :[/bold yellow] [white]{'✔ Active' if shodan_key else '✘ No Key'}[/white]\n"
        f"[bold yellow]HIBP   :[/bold yellow] [white]{'✘ Skipped' if no_hibp else ('✔ API Key' if hibp_key else '✔ Free (Domain)')}[/white]\n"
        f"[bold yellow]AI     :[/bold yellow] [white]{ai_provider}[/white]"
        + (f"\n[bold yellow]Model  :[/bold yellow] [white]{ai_model}[/white]" if ai_model else ""),
        title="[cyan]Scan Parameters[/cyan]",
        border_style="yellow",
        padding=(0, 2)
    ))
    console.print()

    safe_domain = domain.replace('/', '_').replace(':', '')
    report_base = output or f"Report_{safe_domain}"

    t = lambda en, tr: tr if lang == 'tr' else en

    # ─── STEP 1: Parallel Passive Recon ─────────────────────────────
    console.print(t("[bold cyan]━━━ [1/6] Passive Recon (Parallel/Async) ━━━━━━━[/bold cyan]",
                    "[bold cyan]━━━ [1/6] Pasif Keşif (Asenkron) ━━━━━━━━━━━━━━━━━[/bold cyan]"))
    recon_data = run_passive_recon(domain, fast, lang)
    alive_count = len([s for s in recon_data.get("alive_subdomains", []) if s["alive"]])
    console.print(t(f"[bold green]  ✔ Passive recon completed — {alive_count} alive hosts[/bold green]\n",
                    f"[bold green]  ✔ Pasif keşif tamamlandı — {alive_count} aktif host[/bold green]\n"))

    # ─── STEP 2: Shodan ──────────────────────────────────────────────
    shodan_data = {}
    if shodan_key:
        console.print(t("[bold cyan]━━━ [2/6] Shodan Intelligence ━━━━━━━━━━━━━━━━━━━━[/bold cyan]",
                        "[bold cyan]━━━ [2/6] Shodan İstihbaratı ━━━━━━━━━━━━━━━━━━━━━[/bold cyan]"))
        shodan_data = query_shodan(recon_data.get("ip_addresses", []), shodan_key, lang)
        console.print(t("[bold green]  ✔ Shodan query completed.[/bold green]\n",
                        "[bold green]  ✔ Shodan sorgusu tamamlandı.[/bold green]\n"))
    else:
        console.print(t("[dim]━━━ [2/6] Shodan ─ Skipped (requires --shodan-key) ━━[/dim]\n",
                        "[dim]━━━ [2/6] Shodan ─ Atlandı (--shodan-key gerekli) ━━[/dim]\n"))

    # ─── STEP 3: HIBP ────────────────────────────────────────────────
    hibp_data = {}
    if not no_hibp:
        console.print(t("[bold cyan]━━━ [3/6] HaveIBeenPwned Breach Check ━━━━━━━━━━[/bold cyan]",
                        "[bold cyan]━━━ [3/6] HaveIBeenPwned Sızıntı Kontrolü ━━━━━━━━[/bold cyan]"))
        emails = extract_emails_from_recon(recon_data)
        hibp_data = run_hibp_check(domain, emails, hibp_key or "", lang)
        console.print(t("[bold green]  ✔ HIBP check completed.[/bold green]\n",
                        "[bold green]  ✔ HIBP kontrolü tamamlandı.[/bold green]\n"))
    else:
        console.print(t("[dim]━━━ [3/6] HIBP ─ Skipped (--no-hibp) ━━━━━━━━━━━━━[/dim]\n",
                        "[dim]━━━ [3/6] HIBP ─ Atlandı (--no-hibp) ━━━━━━━━━━━━━[/dim]\n"))

    # ─── STEP 4: Screenshots ─────────────────────────────────────────
    screenshots = {}
    if not no_screenshot:
        console.print(t("[bold cyan]━━━ [4/6] Screenshots (Playwright) ━━━━━━━━━━━━━━━[/bold cyan]",
                        "[bold cyan]━━━ [4/6] Ekran Görüntüleri (Playwright) ━━━━━━━━━[/bold cyan]"))
        ss_dir = os.path.join(report_base, "3_Screenshots" if lang == 'en' else "3_Ekran_Goruntuleri")
        alive_subs = [s for s in recon_data.get("alive_subdomains", []) if s["alive"]]
        screenshots = screenshot_alive_subdomains(alive_subs[:max_screenshots], ss_dir, lang)
        console.print(t(f"[bold green]  ✔ {len(screenshots)} screenshots taken.[/bold green]\n",
                        f"[bold green]  ✔ {len(screenshots)} ekran görüntüsü alındı.[/bold green]\n"))
    else:
        console.print(t("[dim]━━━ [4/6] Screenshots ─ Skipped ━━━━━━━━━━━━━━━━━━[/dim]\n",
                        "[dim]━━━ [4/6] Ekran Görüntüleri ─ Atlandı ━━━━━━━━━━━━[/dim]\n"))

    # ─── STEP 5: AI Analysis ─────────────────────────────────────────
    ai_analysis = {"raw": "", "success": False, "source": "Skipped"}
    if not no_ai:
        console.print(t("[bold cyan]━━━ [5/6] AI Analysis ━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]",
                        "[bold cyan]━━━ [5/6] Yapay Zeka Analizi ━━━━━━━━━━━━━━━━━━━━━[/bold cyan]"))
        ai_analysis = run_ai_analysis(
            recon_data, lang,
            openai_key=openai_key, gemini_key=gemini_key,
            claude_key=claude_key, groq_key=groq_key,
            ai_model=ai_model,
        )
        src = ai_analysis.get("source", "Unknown")
        if ai_analysis.get("success"):
            console.print(t(f"[bold green]  ✔ AI analysis completed.[/bold green] (Source: [green]{src}[/green])\n",
                            f"[bold green]  ✔ AI analizi tamamlandı.[/bold green] (Kaynak: [green]{src}[/green])\n"))
        else:
            console.print(t(f"[bold red]  ✘ AI analysis failed.[/bold red] (Source: {src})\n",
                            f"[bold red]  ✘ AI analizi başarısız oldu.[/bold red] (Kaynak: {src})\n"))
    else:
        console.print(t("[dim]━━━ [5/6] AI Analysis ─ Skipped (--no-ai) ━━━━━━━━[/dim]\n",
                        "[dim]━━━ [5/6] Yapay Zeka Analizi ─ Atlandı (--no-ai) ━[/dim]\n"))

    # ─── STEP 6: Report ──────────────────────────────────────────────
    console.print(t("[bold cyan]━━━ [6/6] Generating Report ━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]",
                    "[bold cyan]━━━ [6/6] Rapor Oluşturuluyor ━━━━━━━━━━━━━━━━━━━━[/bold cyan]"))
    out_dir = generate_report(
        domain, recon_data, ai_analysis, screenshots, lang,
        shodan_data=shodan_data, hibp_data=hibp_data, output_dir=report_base
    )
    console.print(t(f"[bold green]  ✔ Report directory: {out_dir}/[/bold green]\n",
                    f"[bold green]  ✔ Rapor dizini: {out_dir}/[/bold green]\n"))

    # ─── Summary ─────────────────────────────────────────────────────
    print_summary_table(recon_data, screenshots, shodan_data, hibp_data, lang)

    html_file = "Main_Report.html" if lang == 'en' else "Ana_Rapor.html"
    html_path = os.path.join(out_dir, html_file)
    
    # Export PDF
    if export_pdf:
        console.print("[bold cyan]━━━ Exporting PDF ━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]")
        try:
            from playwright.sync_api import sync_playwright
            pdf_path = os.path.join(out_dir, "Report.pdf")
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                page.goto(f"file://{os.path.abspath(html_path)}")
                page.pdf(path=pdf_path, format="A4", print_background=True)
                browser.close()
            console.print(f"[bold green]  ✔ PDF saved to {pdf_path}[/bold green]\n")
        except Exception as e:
            console.print(f"[red]  ✘ PDF Export failed: {e}[/red]\n")

    # Send Webhook
    if webhook:
        if lang == 'tr':
            console.print("[bold cyan]━━━ Webhook Gönderiliyor ━━━━━━━━━━━━━━━━━━━━━[/bold cyan]")
            title = "Tarama Özeti"
            msg = f"🚨 **SenfoniScan Raporu Tamamlandı!**\nHedef: `{domain}`"
        else:
            console.print("[bold cyan]━━━ Sending Webhook ━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]")
            title = "Recon Summary"
            msg = f"🚨 **SenfoniScan Report Completed!**\nTarget: `{domain}`"
            
        try:
            import requests
            alive_count = len([s for s in recon_data.get("alive_subdomains", []) if s["alive"]])
            payload = {
                "content": msg,
                "embeds": [{
                    "title": title,
                    "color": 5814783,
                    "fields": [
                        {"name": "Total Subs" if lang == 'en' else "Toplam Sub", "value": str(len(recon_data.get("subdomains_raw", []))), "inline": True},
                        {"name": "Alive Hosts" if lang == 'en' else "Aktif Host", "value": str(alive_count), "inline": True},
                        {"name": "Secrets Found" if lang == 'en' else "Bulunan Sır", "value": str(len(recon_data.get("secrets", []))), "inline": True}
                    ]
                }]
            }
            requests.post(webhook, json=payload, timeout=5)
            if lang == 'tr':
                console.print("[bold green]  ✔ Webhook gönderildi.[/bold green]\n")
            else:
                console.print("[bold green]  ✔ Webhook sent.[/bold green]\n")
        except Exception as e:
            console.print(f"[dim]  ✘ Webhook failure: {e}[/dim]\n")

    console.print()
    if lang == 'tr':
        console.print(Panel(
            f"[bold green]✔ Tüm işlemler tamamlandı![/bold green]\n\n"
            f"[white]Rapor dizini :[/white] [cyan]{out_dir}/[/cyan]\n"
            f"[white]Görsel rapor :[/white] [cyan]{html_path}[/cyan]\n\n"
            f"[dim]Tarayıcıda açmak için:[/dim]\n"
            f"[yellow]  xdg-open {html_path}[/yellow]",
            border_style="green",
            padding=(1, 2)
        ))
    else:
        console.print(Panel(
            f"[bold green]✔ All operations completed![/bold green]\n\n"
            f"[white]Report directory :[/white] [cyan]{out_dir}/[/cyan]\n"
            f"[white]Visual report    :[/white] [cyan]{html_path}[/cyan]\n\n"
            f"[dim]To open in browser:[/dim]\n"
            f"[yellow]  xdg-open {html_path}[/yellow]",
            border_style="green",
            padding=(1, 2)
        ))


if __name__ == '__main__':
    _auto_setup()
    main()
