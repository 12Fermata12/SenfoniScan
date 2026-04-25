"""
SenfoniScan - Multi-Provider AI Engine
Supports: Ollama (local), OpenAI, Google Gemini, Anthropic Claude, Groq
No simulations. Real AI only.
"""
import json
from rich.console import Console

console = Console()

OLLAMA_MODEL = "llama3"


def _build_prompt(recon_data: dict, lang: str) -> str:
    domain = recon_data["domain"]
    alive = [s for s in recon_data.get("alive_subdomains", []) if s["alive"]]
    subdomains_list = "\n".join([
        f"- {s['host']} (HTTP {s.get('http_status','?')}, Server: {s.get('server','?')}, "
        f"Title: {s.get('title','?')})"
        for s in alive
    ])
    dns_txt = json.dumps(recon_data.get("dns_records", {}), indent=2, ensure_ascii=False)
    wayback = "\n".join(recon_data.get("wayback_urls", [])[:15])
    cloud = json.dumps(recon_data.get("cloud_buckets", []), ensure_ascii=False)
    ips = ", ".join(recon_data.get("ip_addresses", []))
    whois_txt = json.dumps(recon_data.get("whois_asn", {}), indent=2, ensure_ascii=False)
    secrets_txt = json.dumps(recon_data.get("secrets", []), indent=2, ensure_ascii=False)

    if lang == 'tr':
        return f"""Sen bir siber güvenlik uzmanısın. '{domain}' domaininde yapılan pasif keşif sonuçlarını analiz et.

=== IP ADRESLERİ ===
{ips or "Bulunamadı"}

=== DNS KAYITLARI ===
{dns_txt}

=== AKTİF SUBDOMAİNLER ({len(alive)} adet) ===
{subdomains_list or "Aktif subdomain bulunamadı."}

=== WAYBACK MACHINE ARŞİV URL'LERİ ===
{wayback or "Arşiv verisi bulunamadı."}

=== POTANSİYEL HASSAS DOSYALAR (SECRETS) ===
{secrets_txt}

=== WHOIS & ASN BİLGİSİ ===
{whois_txt}

=== CLOUD BUCKET KONTROL ===
{cloud or "Cloud bucket bulunamadı."}

Detaylı Türkçe analiz yaz:

## Genel Değerlendirme
Domain hakkında ne öğrenilebildi? Altyapı, hosting, dikkat çekici noktalar.

## Kritik Bulgular
Güvenlik açısından riskli subdomainler (admin, cpanel, test, dev, staging vb.), açık servisler, eski URL'ler.

## Teknoloji Yığını
Sunucu başlıklarından, DNS kayıtlarından tespit edilen teknolojiler ve versiyonlar.

## Saldırı Yüzeyi Analizi
Potansiyel saldırı vektörleri, subdomain takeover riskleri, bilgi sızıntısı.

## Öneriler
Daha derinlemesine inceleme için yapılması gerekenler.

## Klasörler ve Raporlar
Sadece liste (satır başına bir tane):
1_DNS_Analizi/dns_kayitlari.md
2_Aktif_Subdomainler/aktif_subdomainler.md
(Bulunan verilere göre ekle)

Markdown formatında yaz."""

    else:
        return f"""You are a cybersecurity expert. Analyze passive recon data for '{domain}'.

=== IP ADDRESSES ===
{ips or "Not found"}

=== DNS RECORDS ===
{dns_txt}

=== ALIVE SUBDOMAINS ({len(alive)}) ===
{subdomains_list or "No alive subdomains found."}

=== WAYBACK MACHINE URLS ===
{wayback or "No archive data found."}

=== POTENTIAL SECRETS ===
{secrets_txt}

=== WHOIS & ASN INFORMATION ===
{whois_txt}

=== CLOUD BUCKET CHECK ===
{cloud or "No cloud buckets found."}

Write detailed analysis:

## General Assessment
What was discovered? Infrastructure, hosting, key observations.

## Critical Findings
Risky subdomains (admin, cpanel, test, dev, staging), exposed services, old URLs.

## Technology Stack
Technologies identified from server headers, DNS records, versions.

## Attack Surface Analysis
Potential attack vectors, subdomain takeover risks, information leakage.

## Recommendations
Next steps for deeper investigation.

## Folders and Reports
List only (one per line):
1_DNS_Analysis/dns_records.md
2_Alive_Subdomains/alive_subdomains.md
(Add based on found data)

Write in Markdown format."""


def run_ai_analysis(recon_data: dict, lang: str,
                    openai_key: str = None, gemini_key: str = None,
                    claude_key: str = None, groq_key: str = None,
                    ai_model: str = None) -> dict:
    """Run AI analysis with the best available provider. Priority:
    1. OpenAI (if key provided)
    2. Gemini (if key provided)
    3. Claude (if key provided)
    4. Groq (if key provided)
    5. Ollama (local, no key needed)
    """
    prompt = _build_prompt(recon_data, lang)

    if openai_key:
        return _run_openai(prompt, openai_key, ai_model, lang)
    elif gemini_key:
        return _run_gemini(prompt, gemini_key, ai_model, lang)
    elif claude_key:
        return _run_claude(prompt, claude_key, ai_model, lang)
    elif groq_key:
        return _run_groq(prompt, groq_key, ai_model, lang)
    else:
        return _run_ollama(prompt, ai_model, lang)


# ─── OpenAI ──────────────────────────────────────────────────────────
def _run_openai(prompt: str, api_key: str, model: str = None, lang: str = 'en') -> dict:
    model = model or "gpt-4o"
    t = lambda en, tr: tr if lang == 'tr' else en
    try:
        from openai import OpenAI
        client = OpenAI(api_key=api_key)
        console.print(t(f"  [magenta][AI] Running analysis with OpenAI ({model})...[/magenta]",
                        f"  [magenta][AI] OpenAI ({model}) ile analiz çalıştırılıyor...[/magenta]"))
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=4096,
        )
        raw = response.choices[0].message.content
        console.print(t(f"  [green]  ✔ OpenAI response received ({len(raw)} chars)[/green]",
                        f"  [green]  ✔ OpenAI yanıtı alındı ({len(raw)} karakter)[/green]"))
        return {"raw": raw, "success": True, "source": f"OpenAI ({model})"}
    except Exception as e:
        console.print(t(f"  [red]  [!] OpenAI error: {e}[/red]", f"  [red]  [!] OpenAI hatası: {e}[/red]"))
        return {"raw": f"AI Analysis Error (OpenAI): {e}", "success": False, "source": "OpenAI"}


# ─── Google Gemini ───────────────────────────────────────────────────
def _run_gemini(prompt: str, api_key: str, model: str = None, lang: str = 'en') -> dict:
    model = model or "gemini-2.5-flash"
    t = lambda en, tr: tr if lang == 'tr' else en
    try:
        import requests
        console.print(t(f"  [magenta][AI] Running analysis with Google Gemini ({model})...[/magenta]",
                        f"  [magenta][AI] Google Gemini ({model}) ile analiz çalıştırılıyor...[/magenta]"))
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        resp = requests.post(url, json=payload, timeout=120)
        if resp.status_code == 200:
            data = resp.json()
            raw = data["candidates"][0]["content"]["parts"][0]["text"]
            console.print(t(f"  [green]  ✔ Gemini response received ({len(raw)} chars)[/green]",
                            f"  [green]  ✔ Gemini yanıtı alındı ({len(raw)} karakter)[/green]"))
            return {"raw": raw, "success": True, "source": f"Google Gemini ({model})"}
        else:
            err = resp.json().get("error", {}).get("message", resp.text[:200])
            raise Exception(err)
    except Exception as e:
        console.print(t(f"  [red]  [!] Gemini error: {e}[/red]", f"  [red]  [!] Gemini hatası: {e}[/red]"))
        return {"raw": f"AI Analysis Error (Gemini): {e}", "success": False, "source": "Gemini"}


# ─── Anthropic Claude ────────────────────────────────────────────────
def _run_claude(prompt: str, api_key: str, model: str = None, lang: str = 'en') -> dict:
    model = model or "claude-sonnet-4-20250514"
    t = lambda en, tr: tr if lang == 'tr' else en
    try:
        import requests
        console.print(t(f"  [magenta][AI] Running analysis with Anthropic Claude ({model})...[/magenta]",
                        f"  [magenta][AI] Anthropic Claude ({model}) ile analiz çalıştırılıyor...[/magenta]"))
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": model,
                "max_tokens": 4096,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=120,
        )
        if resp.status_code == 200:
            raw = resp.json()["content"][0]["text"]
            console.print(t(f"  [green]  ✔ Claude response received ({len(raw)} chars)[/green]",
                            f"  [green]  ✔ Claude yanıtı alındı ({len(raw)} karakter)[/green]"))
            return {"raw": raw, "success": True, "source": f"Anthropic Claude ({model})"}
        else:
            err = resp.json().get("error", {}).get("message", resp.text[:200])
            raise Exception(err)
    except Exception as e:
        console.print(t(f"  [red]  [!] Claude error: {e}[/red]", f"  [red]  [!] Claude hatası: {e}[/red]"))
        return {"raw": f"AI Analysis Error (Claude): {e}", "success": False, "source": "Claude"}


# ─── Groq ────────────────────────────────────────────────────────────
def _run_groq(prompt: str, api_key: str, model: str = None, lang: str = 'en') -> dict:
    model = model or "llama-3.3-70b-versatile"
    t = lambda en, tr: tr if lang == 'tr' else en
    try:
        import requests
        console.print(t(f"  [magenta][AI] Running analysis with Groq ({model})...[/magenta]",
                        f"  [magenta][AI] Groq ({model}) ile analiz çalıştırılıyor...[/magenta]"))
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 4096,
            },
            timeout=60,
        )
        if resp.status_code == 200:
            raw = resp.json()["choices"][0]["message"]["content"]
            console.print(t(f"  [green]  ✔ Groq response received ({len(raw)} chars)[/green]",
                            f"  [green]  ✔ Groq yanıtı alındı ({len(raw)} karakter)[/green]"))
            return {"raw": raw, "success": True, "source": f"Groq ({model})"}
        else:
            err = resp.json().get("error", {}).get("message", resp.text[:200])
            raise Exception(err)
    except Exception as e:
        console.print(t(f"  [red]  [!] Groq error: {e}[/red]", f"  [red]  [!] Groq hatası: {e}[/red]"))
        return {"raw": f"AI Analysis Error (Groq): {e}", "success": False, "source": "Groq"}


# ─── Ollama (Local) ─────────────────────────────────────────────────
def _run_ollama(prompt: str, model: str = None, lang: str = 'en') -> dict:
    model = model or OLLAMA_MODEL
    t = lambda en, tr: tr if lang == 'tr' else en
    try:
        import ollama
        console.print(t(f"  [magenta][AI] Running analysis with Ollama ({model})...[/magenta]",
                        f"  [magenta][AI] Ollama ({model}) ile yerel analiz çalıştırılıyor...[/magenta]"))
        response = ollama.chat(
            model=model,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = response['message']['content']
        console.print(t(f"  [green]  ✔ Ollama response received ({len(raw)} chars)[/green]",
                        f"  [green]  ✔ Ollama yanıtı alındı ({len(raw)} karakter)[/green]"))
        return {"raw": raw, "success": True, "source": f"Ollama ({model})"}
    except Exception as e:
        console.print(t(f"  [yellow]  [!] Ollama error: {e}[/yellow]", f"  [yellow]  [!] Ollama hatası: {e}[/yellow]"))
        err_en = (f"AI Analysis Skipped: No AI provider configured.\n\nError: {e}\n\n"
                  "Solution: Provide --openai-key, --gemini-key, --claude-key, or --groq-key parameters.")
        err_tr = (f"Yapay Zeka Analizi Atlandı: Yapılandırılmış AI sağlayıcısı yok.\n\nHata: {e}\n\n"
                  "Çözüm: --openai-key, --gemini-key, --claude-key veya --groq-key parametrelerinden birini sağlayın.")
        return {
            "raw": t(err_en, err_tr),
            "success": False,
            "source": "Ollama (Local)"
        }
