"""
SenfoniScan - Screenshot Module
Uses Playwright headless Chromium to capture web pages.
Handles SSL certificate errors gracefully.
"""
import os
from rich.console import Console

console = Console()


def take_screenshot(url: str, output_path: str) -> bool:
    """Take a screenshot of a URL and save it to output_path. Returns True on success."""
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                viewport={"width": 1280, "height": 900},
                ignore_https_errors=True,  # Ignore SSL certificate errors
                user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )
            page = context.new_page()
            page.goto(url, timeout=15000, wait_until="networkidle")
            page.screenshot(path=output_path, full_page=False)
            browser.close()
        return True
    except Exception as e:
        console.print(f"[yellow]    [!] Failed to capture screenshot ({url}): {e}[/yellow]")
        return False


def screenshot_alive_subdomains(alive_subdomains: list, screenshots_dir: str, lang: str = "en") -> dict:
    """Screenshot all alive subdomains. Returns dict of host -> screenshot_path."""
    t = lambda en, tr: tr if lang == 'tr' else en
    
    try:
        os.makedirs(screenshots_dir, exist_ok=True)
    except PermissionError:
        console.print(t(f"[red]  [!] Failed to create directory (permission error): {screenshots_dir}[/red]",
                        f"[red]  [!] Dizin oluşturulamadı (izin hatası): {screenshots_dir}[/red]"))
        console.print(t("[yellow]      Hint: Old report folder might be owned by root. Use --output to specify a different directory.[/yellow]",
                        "[yellow]      İpucu: Eski rapor klasörü root'a ait olabilir. Farklı bir dizin belirtmek için --output kullanın.[/yellow]"))
        return {}
    results = {}
    for sub in alive_subdomains:
        if not sub.get("alive"):
            continue
        url = sub.get("url")
        host = sub.get("host", "unknown")
        safe_name = host.replace(".", "_").replace("/", "_")
        out_path = os.path.join(screenshots_dir, f"{safe_name}.png")
        console.print(t(f"  [cyan][📷] Taking screenshot: {url}[/cyan]",
                        f"  [cyan][📷] Ekran görüntüsü alınıyor: {url}[/cyan]"))
        success = take_screenshot(url, out_path)
        if success:
            results[host] = out_path
            console.print(t(f"  [green]    ✔ Saved → {out_path}[/green]",
                            f"  [green]    ✔ Kaydedildi → {out_path}[/green]"))
    return results
