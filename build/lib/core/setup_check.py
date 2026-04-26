"""
SenfoniScan - Auto Setup & Dependency Check
Runs at startup: installs missing pip packages, playwright browser, checks ollama.
"""
import sys
import subprocess
import importlib
import os
from pathlib import Path

REQUIRED_PACKAGES = {
    "rich": "rich",
    "click": "click",
    "requests": "requests",
    "dns": "dnspython",
    "aiohttp": "aiohttp",
    "playwright": "playwright",
    "jinja2": "jinja2",
    "pydantic": "pydantic",
    "shodan": "shodan",
    "ollama": "ollama",
    "openai": "openai",
    "whois": "python-whois",
    "ipwhois": "ipwhois",
}


def _print(msg: str, color: str = "white"):
    """Simple colored print without rich (used before rich is confirmed installed)."""
    colors = {
        "red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
        "cyan": "\033[96m", "white": "\033[97m", "dim": "\033[2m",
    }
    reset = "\033[0m"
    print(f"{colors.get(color, '')}{msg}{reset}")


def check_and_install_packages() -> bool:
    """Check all required pip packages and install missing ones. Returns True if any were installed."""
    missing = []
    for import_name, pip_name in REQUIRED_PACKAGES.items():
        try:
            importlib.import_module(import_name)
        except ImportError:
            missing.append(pip_name)

    if not missing:
        return False

    _print(f"\n[*] Eksik kütüphaneler tespit edildi: {', '.join(missing)}", "yellow")
    _print("[*] Otomatik kuruluyor...\n", "cyan")

    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--quiet"] + missing,
        capture_output=False,
        text=True,
    )

    if result.returncode != 0:
        _print("[!] Pip kurulumu başarısız oldu. Lütfen manuel olarak çalıştırın:", "red")
        _print(f"    pip install {' '.join(missing)}", "yellow")
        sys.exit(1)

    _print(f"\n[✔] {len(missing)} paket başarıyla kuruldu.\n", "green")
    return True


def check_playwright_browser():
    """Check if Playwright Chromium is installed, install if missing."""
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            # Try to get the executable path
            browser_path = p.chromium.executable_path
            if not Path(browser_path).exists():
                raise FileNotFoundError("Browser not found")
        return  # All good
    except Exception:
        _print("\n[*] Playwright Chromium tarayıcısı bulunamadı, kuruluyor...", "yellow")
        result = subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            capture_output=False,
            text=True,
        )
        if result.returncode == 0:
            _print("[✔] Playwright Chromium başarıyla kuruldu.\n", "green")
        else:
            _print("[!] Playwright Chromium kurulamadı. Ekran görüntüsü devre dışı olacak.", "yellow")


def check_ollama() -> bool:
    """Check if Ollama is installed and running. Returns True if available."""
    # Check if binary exists
    ollama_installed = subprocess.run(
        ["which", "ollama"], capture_output=True, text=True
    ).returncode == 0

    if not ollama_installed:
        _print("\n[!] Ollama kurulu değil — Gerçek AI analizi için kurmanız önerilir:", "yellow")
        _print("    curl -fsSL https://ollama.com/install.sh | sh", "dim")
        _print("    ollama pull llama3\n", "dim")
        return False

    # Check if service is running
    try:
        import requests as req
        resp = req.get("http://localhost:11434/api/tags", timeout=3)
        if resp.status_code == 200:
            models = [m["name"] for m in resp.json().get("models", [])]
            if models:
                _print(f"[✔] Ollama aktif — Yüklü modeller: {', '.join(models)}", "green")
            else:
                _print("[!] Ollama çalışıyor ama hiç model yüklü değil.", "yellow")
                _print("    Şu komutu çalıştırın: ollama pull llama3\n", "dim")
            return True
    except Exception:
        pass

    _print("\n[!] Ollama kurulu ama çalışmıyor. Başlatmak için:", "yellow")
    _print("    ollama serve &\n", "dim")
    return False


def run_setup(skip_ollama_check: bool = False):
    """
    Full setup pipeline:
    1. Install missing pip packages
    2. Install playwright browser
    3. Check ollama status
    """
    any_installed = check_and_install_packages()

    # If packages were just installed, we need to reimport them
    if any_installed:
        # Invalidate import cache
        importlib.invalidate_caches()

    check_playwright_browser()

    if not skip_ollama_check:
        check_ollama()
