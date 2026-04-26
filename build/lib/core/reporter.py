"""
SenfoniScan - Report Generator
Creates a rich folder structure with Markdown + HTML reports.
The folder structure is dynamically driven by AI analysis output.
"""
import os
import re
import base64
from datetime import datetime
from jinja2 import Template


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="{{ lang }}">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SenfoniScan Report - {{ domain }}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: #0d1117;
      color: #c9d1d9;
      min-height: 100vh;
    }
    .header {
      background: linear-gradient(135deg, #161b22 0%, #1c2128 100%);
      border-bottom: 1px solid #30363d;
      padding: 40px;
      display: flex;
      align-items: center;
      gap: 20px;
    }
    .logo { font-size: 3em; }
    .header-text h1 { font-size: 2em; color: #58a6ff; font-weight: 700; letter-spacing: -0.5px; }
    .header-text p { color: #8b949e; margin-top: 5px; font-size: 0.95em; }
    .badges { display: flex; gap: 10px; margin-top: 12px; flex-wrap: wrap; }
    .badge {
      padding: 4px 12px; border-radius: 20px; font-size: 0.78em; font-weight: 600;
      border: 1px solid;
    }
    .badge-blue { color: #58a6ff; border-color: #1f6feb; background: #1f6feb22; }
    .badge-green { color: #3fb950; border-color: #238636; background: #23863622; }
    .badge-yellow { color: #d29922; border-color: #9e6a03; background: #9e6a0322; }
    .badge-red { color: #f85149; border-color: #da3633; background: #da363322; }
    .container { max-width: 1200px; margin: 0 auto; padding: 40px 20px; }
    .section {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 12px;
      padding: 28px;
      margin-bottom: 24px;
    }
    .section-title {
      font-size: 1.2em; font-weight: 700; color: #e6edf3;
      margin-bottom: 18px; padding-bottom: 12px;
      border-bottom: 1px solid #30363d;
      display: flex; align-items: center; gap: 10px;
    }
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; }
    .stat-card {
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 10px;
      padding: 20px;
      text-align: center;
    }
    .stat-num { font-size: 2.5em; font-weight: 800; color: #58a6ff; }
    .stat-label { font-size: 0.82em; color: #8b949e; margin-top: 4px; }
    table {
      width: 100%; border-collapse: collapse;
      font-size: 0.88em;
    }
    th {
      text-align: left; padding: 10px 14px;
      background: #1c2128; color: #8b949e;
      font-weight: 600; font-size: 0.85em;
      border-bottom: 1px solid #30363d;
    }
    td {
      padding: 10px 14px;
      border-bottom: 1px solid #21262d;
      vertical-align: middle;
    }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: #1c2128; }
    .status-alive { color: #3fb950; font-weight: 600; }
    .status-dead { color: #f85149; }
    .status-200 { color: #3fb950; }
    .status-301, .status-302 { color: #d29922; }
    .status-403 { color: #f85149; }
    .code-tag {
      background: #1c2128; border: 1px solid #30363d;
      padding: 2px 8px; border-radius: 6px;
      font-family: monospace; font-size: 0.9em; color: #79c0ff;
    }
    .screenshot-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(380px, 1fr));
      gap: 20px; margin-top: 10px;
    }
    .screenshot-card {
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 10px;
      overflow: hidden;
    }
    .screenshot-card img {
      width: 100%; display: block;
      border-bottom: 1px solid #30363d;
    }
    .screenshot-card .ss-label {
      padding: 10px 14px;
      font-family: monospace; font-size: 0.85em; color: #8b949e;
    }
    .ai-content {
      line-height: 1.8; font-size: 0.95em;
    }
    .ai-content h2 { color: #58a6ff; margin: 20px 0 10px; font-size: 1.1em; }
    .ai-content h3 { color: #79c0ff; margin: 16px 0 8px; font-size: 1em; }
    .ai-content ul { padding-left: 20px; margin: 8px 0; }
    .ai-content li { margin: 4px 0; }
    .ai-content code {
      background: #1c2128; padding: 1px 6px;
      border-radius: 4px; font-size: 0.9em; color: #f0883e;
    }
    .ai-content strong { color: #e6edf3; }
    .dns-grid { display: grid; grid-template-columns: 120px 1fr; gap: 0; }
    .dns-key {
      padding: 8px 14px; background: #1c2128;
      color: #79c0ff; font-family: monospace; font-size: 0.85em;
      border-bottom: 1px solid #21262d; font-weight: 600;
    }
    .dns-val {
      padding: 8px 14px; font-family: monospace; font-size: 0.82em;
      border-bottom: 1px solid #21262d; color: #8b949e; word-break: break-all;
    }
    .wayback-list { list-style: none; padding: 0; }
    .wayback-list li {
      padding: 6px 10px; border-bottom: 1px solid #21262d;
      font-family: monospace; font-size: 0.82em;
    }
    .wayback-list li:last-child { border-bottom: none; }
    .wayback-list a { color: #58a6ff; text-decoration: none; }
    .wayback-list a:hover { text-decoration: underline; }
    .footer {
      text-align: center; padding: 40px;
      border-top: 1px solid #30363d;
      color: #484f58; font-size: 0.82em;
    }
    .no-data { color: #484f58; font-style: italic; padding: 10px 0; }
    .risk-high { color: #f85149; font-weight: 700; }
    .risk-med { color: #d29922; font-weight: 600; }
    .risk-low { color: #3fb950; }
  </style>
</head>
<body>
<div class="header">
  <div class="logo">🔍</div>
  <div class="header-text">
    <h1>SenfoniScan Report</h1>
    <p>{{ domain }} &nbsp;|&nbsp; {{ scan_date }} &nbsp;|&nbsp; {{ lang_label }}</p>
    <div class="badges">
      <span class="badge badge-blue">Pasif Keşif</span>
      <span class="badge badge-green">{{ total_alive }} Aktif Subdomain</span>
      <span class="badge badge-yellow">{{ total_subs }} Toplam Subdomain</span>
      {% if has_cloud %}<span class="badge badge-red">⚠ Cloud Bucket</span>{% endif %}
    </div>
  </div>
</div>

<div class="container">

  <!-- Stats -->
  <div class="section">
    <div class="section-title">📊 {{ "Özet İstatistikler" if lang == "tr" else "Summary Statistics" }}</div>
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-num">{{ total_subs }}</div>
        <div class="stat-label">{{ "Toplam Subdomain" if lang == "tr" else "Total Subdomains" }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color:#3fb950">{{ total_alive }}</div>
        <div class="stat-label">{{ "Aktif" if lang == "tr" else "Alive" }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color:#f85149">{{ total_dead }}</div>
        <div class="stat-label">{{ "Erişilemiyor" if lang == "tr" else "Dead" }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color:#d29922">{{ wayback_count }}</div>
        <div class="stat-label">{{ "Arşiv URL" if lang == "tr" else "Archive URLs" }}</div>
      </div>
    </div>
  </div>

  <!-- AI Analysis -->
  <div class="section">
    <div class="section-title">🤖 {{ "Yapay Zeka Analizi" if lang == "tr" else "AI Analysis" }}
      {% if not ollama_used %}<span style="font-size:0.7em; color:#484f58; font-weight:400"> (Ollama bağlı değil - yerel analiz)</span>{% endif %}
    </div>
    <div class="ai-content">{{ ai_html }}</div>
  </div>

  <!-- Subdomains Table -->
  <div class="section">
    <div class="section-title">🌐 {{ "Subdomain Haritası" if lang == "tr" else "Subdomain Map" }}</div>
    <table>
      <thead>
        <tr>
          <th>Host</th>
          <th>{{ "Durum" if lang == "tr" else "Status" }}</th>
          <th>HTTP</th>
          <th>Server</th>
          <th>{{ "Sayfa Başlığı" if lang == "tr" else "Page Title" }}</th>
        </tr>
      </thead>
      <tbody>
      {% for sub in alive_subdomains %}
        <tr>
          <td><span class="code-tag">{{ sub.host }}</span></td>
          <td>
            {% if sub.alive %}
              <span class="status-alive">● Aktif</span>
            {% else %}
              <span class="status-dead">✘ Erişilemiyor</span>
            {% endif %}
          </td>
          <td>
            <span class="status-{{ sub.http_status or 0 }}">{{ sub.http_status or "-" }}</span>
          </td>
          <td>{{ sub.server or "-" }}</td>
          <td style="color:#8b949e; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
            {{ sub.title or "-" }}
          </td>
        </tr>
      {% else %}
        <tr><td colspan="5" class="no-data">{{ "Subdomain bulunamadı." if lang == "tr" else "No subdomains found." }}</td></tr>
      {% endfor %}
      </tbody>
    </table>
  </div>

  <!-- Screenshots -->
  {% if screenshots %}
  <div class="section">
    <div class="section-title">📷 {{ "Ekran Görüntüleri" if lang == "tr" else "Screenshots" }}</div>
    <div class="screenshot-grid">
      {% for host, img_b64 in screenshots.items() %}
      <div class="screenshot-card">
        <img src="data:image/png;base64,{{ img_b64 }}" alt="{{ host }}" loading="lazy">
        <div class="ss-label">{{ host }}</div>
      </div>
      {% endfor %}
    </div>
  </div>
  {% endif %}

  <!-- DNS Records -->
  <div class="section">
    <div class="section-title">🗂 {{ "DNS Kayıtları" if lang == "tr" else "DNS Records" }}</div>
    <div class="dns-grid">
      {% for rtype, values in dns_records.items() %}
        {% if values %}
          {% for v in values %}
            <div class="dns-key">{{ rtype }}</div>
            <div class="dns-val">{{ v }}</div>
          {% endfor %}
        {% endif %}
      {% endfor %}
    </div>
  </div>

  <!-- Wayback URLs -->
  {% if wayback_urls %}
  <div class="section">
    <div class="section-title">⏳ {{ "Wayback Machine Arşivi" if lang == "tr" else "Wayback Machine Archive" }}</div>
    <ul class="wayback-list">
      {% for url in wayback_urls %}
        <li><a href="{{ url }}" target="_blank">{{ url }}</a></li>
      {% endfor %}
    </ul>
  </div>
  {% endif %}

  <!-- Cloud Buckets -->
  {% if cloud_buckets %}
  <div class="section">
    <div class="section-title">☁ {{ "Cloud Bucket Analizi" if lang == "tr" else "Cloud Bucket Analysis" }}</div>
    <table>
      <thead><tr><th>Bucket</th><th>{{ "HTTP Kodu" if lang == "tr" else "HTTP Code" }}</th><th>{{ "Erişim" if lang == "tr" else "Access" }}</th></tr></thead>
      <tbody>
        {% for b in cloud_buckets %}
        <tr>
          <td><span class="code-tag">{{ b.bucket }}</span></td>
          <td>{{ b.status }}</td>
          <td>{% if b.accessible %}<span class="risk-high">⚠ AÇIK!</span>{% else %}<span class="risk-low">Kapalı</span>{% endif %}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}
  <!-- Shodan -->
  {% if shodan_hosts %}
  <div class="section">
    <div class="section-title">🔍 {{ "Shodan İstihbaratı" if lang == "tr" else "Shodan Intelligence" }}</div>
    <table>
      <thead><tr><th>IP</th><th>{{ "Organizasyon" if lang == "tr" else "Org" }}</th><th>ISP</th><th>{{ "Açık Portlar" if lang == "tr" else "Open Ports" }}</th><th>CVE</th></tr></thead>
      <tbody>
        {% for h in shodan_hosts %}
        <tr>
          <td><span class="code-tag">{{ h.ip }}</span></td>
          <td>{{ h.org }}</td>
          <td>{{ h.isp }}</td>
          <td>{{ h.ports | join(', ') }}</td>
          <td>{% if h.vulns %}<span class="risk-high">⚠ {{ h.vulns | join(', ') }}</span>{% else %}<span class="risk-low">Temiz</span>{% endif %}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

  <!-- HIBP -->
  {% if hibp_breaches %}
  <div class="section">
    <div class="section-title">📧 {{ "HIBP Veri Sızıntısı" if lang == "tr" else "HIBP Data Breaches" }}</div>
    <table>
      <thead><tr><th>{{ "Sızıntı Adı" if lang == "tr" else "Breach Name" }}</th><th>{{ "Tarih" if lang == "tr" else "Date" }}</th><th>{{ "Etkilenen" if lang == "tr" else "Pwned" }}</th><th>{{ "Veri Türleri" if lang == "tr" else "Data Types" }}</th></tr></thead>
      <tbody>
        {% for b in hibp_breaches %}
        <tr>
          <td><span class="code-tag">{{ b.name }}</span></td>
          <td>{{ b.breach_date }}</td>
          <td class="risk-{{ 'high' if b.pwn_count > 1000000 else 'med' }}">{{ "{:,}".format(b.pwn_count) }}</td>
          <td style="color:#8b949e; font-size:0.82em">{{ b.data_classes[:4] | join(', ') }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% endif %}

</div>
<div class="footer">
  SenfoniScan v2.0 &nbsp;|&nbsp; {{ scan_date }} &nbsp;|&nbsp; Yalnızca yetkili sistemlerde kullanın.
</div>
</body>
</html>
"""


def _md_to_simple_html(md: str) -> str:
    """Simple Markdown → HTML converter."""
    import re
    lines = md.split('\n')
    html_lines = []
    for line in lines:
        line = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', line)
        line = re.sub(r'`(.+?)`', r'<code>\1</code>', line)
        if line.startswith('## '):
            html_lines.append(f'<h2>{line[3:]}</h2>')
        elif line.startswith('### '):
            html_lines.append(f'<h3>{line[4:]}</h3>')
        elif line.startswith('- ') or line.startswith('* '):
            html_lines.append(f'<li>{line[2:]}</li>')
        elif line.strip() == '':
            html_lines.append('<br>')
        else:
            html_lines.append(f'<p>{line}</p>')
    return '\n'.join(html_lines)


def _parse_ai_folders(ai_raw: str, lang: str) -> list:
    """Extract folder/file suggestions from AI output."""
    folders = []
    marker = "Klasörler ve Raporlar" if lang == 'tr' else "Folders and Reports"
    in_section = False
    for line in ai_raw.split('\n'):
        if marker in line:
            in_section = True
            continue
        if in_section:
            line = line.strip().lstrip('- *0123456789.')
            if '/' in line and line:
                folders.append(line.strip())
            elif in_section and line.startswith('##'):
                break
    return folders


def generate_report(domain: str, recon_data: dict, ai_analysis: dict,
                    screenshots: dict, lang: str,
                    shodan_data: dict = None, hibp_data: dict = None,
                    output_dir: str = None):
    """Generate full report folder structure with HTML and MD files."""
    safe_domain = domain.replace('/', '_').replace(':', '')
    base_dir = output_dir or f"Rapor_{safe_domain}"
    os.makedirs(base_dir, exist_ok=True)

    alive = [s for s in recon_data.get("alive_subdomains", []) if s["alive"]]
    ai_raw = ai_analysis.get("raw", "")
    ollama_used = ai_analysis.get("ollama_used", False)

    # --- Parse AI-suggested folders and create them ---
    ai_folders = _parse_ai_folders(ai_raw, lang)
    for folder_file in ai_folders:
        parts = folder_file.split('/')
        folder = os.path.join(base_dir, parts[0])
        os.makedirs(folder, exist_ok=True)

    # --- Build screenshot base64 dict for embedding in HTML ---
    screenshots_b64 = {}
    for host, path in screenshots.items():
        try:
            with open(path, 'rb') as f:
                screenshots_b64[host] = base64.b64encode(f.read()).decode()
        except Exception:
            pass

    shodan_hosts = (shodan_data or {}).get("hosts", [])
    hibp_breaches = (hibp_data or {}).get("domain_breaches", [])

    lang_label = "Türkçe" if lang == 'tr' else "English"
    template = Template(HTML_TEMPLATE)
    html_out = template.render(
        domain=domain,
        lang=lang,
        lang_label=lang_label,
        scan_date=recon_data.get("scan_date", ""),
        total_subs=len(recon_data.get("subdomains_raw", [])),
        total_alive=len(alive),
        total_dead=len(recon_data.get("alive_subdomains", [])) - len(alive),
        wayback_count=len(recon_data.get("wayback_urls", [])),
        has_cloud=any(b.get("accessible") for b in recon_data.get("cloud_buckets", [])),
        alive_subdomains=recon_data.get("alive_subdomains", []),
        dns_records=recon_data.get("dns_records", {}),
        wayback_urls=recon_data.get("wayback_urls", []),
        cloud_buckets=recon_data.get("cloud_buckets", []),
        screenshots=screenshots_b64,
        ai_html=_md_to_simple_html(ai_raw),
        ollama_used=ollama_used,
        shodan_hosts=shodan_hosts,
        hibp_breaches=hibp_breaches,
    )

    main_html = "Ana_Rapor.html" if lang == 'tr' else "Main_Report.html"
    with open(os.path.join(base_dir, main_html), 'w', encoding='utf-8') as f:
        f.write(html_out)

    # --- Main Markdown Report ---
    main_md = "Ana_Rapor.md" if lang == 'tr' else "Main_Report.md"
    with open(os.path.join(base_dir, main_md), 'w', encoding='utf-8') as f:
        title = "Ana Rapor" if lang == 'tr' else "Main Report"
        f.write(f"# 🔍 SenfoniScan - {title}\n\n")
        f.write(f"**Domain:** `{domain}`\n")
        f.write(f"**Tarih / Date:** {recon_data.get('scan_date', '')}\n")
        f.write(f"**Dil / Language:** {lang_label}\n\n")
        f.write("---\n\n")
        f.write(ai_raw)
        f.write("\n\n---\n\n")
        f.write(f"*Tam görsel rapor için `{main_html}` dosyasını tarayıcıda açın.*\n")

    # --- Subdomain Detail Report ---
    sub_dir = os.path.join(base_dir, "2_Aktif_Subdomainler" if lang == 'tr' else "2_Alive_Subdomains")
    os.makedirs(sub_dir, exist_ok=True)
    with open(os.path.join(sub_dir, "subdomain_raporu.md" if lang == 'tr' else "subdomain_report.md"), 'w', encoding='utf-8') as f:
        f.write(f"# {'Subdomain Raporu' if lang == 'tr' else 'Subdomain Report'} - {domain}\n\n")
        f.write(f"| Host | {'Durum' if lang == 'tr' else 'Status'} | HTTP | Server | Title |\n")
        f.write("|------|--------|------|--------|-------|\n")
        for sub in recon_data.get("alive_subdomains", []):
            status = "✔ Aktif" if sub["alive"] else "✘ Dead"
            f.write(f"| `{sub['host']}` | {status} | {sub.get('http_status', '-')} | {sub.get('server', '-')} | {sub.get('title', '-')} |\n")

    # --- DNS Report ---
    dns_dir = os.path.join(base_dir, "1_DNS_Analizi" if lang == 'tr' else "1_DNS_Analysis")
    os.makedirs(dns_dir, exist_ok=True)
    with open(os.path.join(dns_dir, "dns_kayitlari.md" if lang == 'tr' else "dns_records.md"), 'w', encoding='utf-8') as f:
        f.write(f"# {'DNS Kayıtları' if lang == 'tr' else 'DNS Records'} - {domain}\n\n")
        for rtype, values in recon_data.get("dns_records", {}).items():
            if values:
                f.write(f"## {rtype}\n")
                for v in values:
                    f.write(f"- `{v}`\n")
                f.write("\n")

    # --- Wayback Report ---
    if recon_data.get("wayback_urls"):
        wb_dir = os.path.join(base_dir, "4_Wayback_Arsivi" if lang == 'tr' else "4_Wayback_Archive")
        os.makedirs(wb_dir, exist_ok=True)
        wb_title = "Wayback Machine Arşiv URL'leri" if lang == 'tr' else "Wayback Machine Archive URLs"
        with open(os.path.join(wb_dir, "eski_urllar.md" if lang == 'tr' else "old_urls.md"), 'w', encoding='utf-8') as f:
            f.write(f"# {wb_title}\n\n")
            for url in recon_data.get("wayback_urls", []):
                f.write(f"- {url}\n")

    # --- Screenshots Report ---
    ss_dir = os.path.join(base_dir, "3_Ekran_Goruntuleri" if lang == 'tr' else "3_Screenshots")
    os.makedirs(ss_dir, exist_ok=True)
    with open(os.path.join(ss_dir, "screenshots.md"), 'w', encoding='utf-8') as f:
        f.write(f"# {'Ekran Görüntüleri' if lang == 'tr' else 'Screenshots'}\n\n")
        for host, path in screenshots.items():
            rel = os.path.relpath(path, base_dir)
            f.write(f"## {host}\n![]({rel})\n\n")

    return base_dir
