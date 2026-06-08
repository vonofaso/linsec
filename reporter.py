import json
from datetime import datetime
from typing import List


class Finding:
    def __init__(self, severity: str, module: str, message: str, cis: str = "", fstec: str = ""):
        self.severity = severity
        self.module = module
        self.message = message
        self.cis = cis
        self.fstec = fstec


class Reporter:
    def __init__(self):
        self.findings: List[Finding] = []

    def add(self, severity: str, module: str, message: str, cis: str = "", fstec: str = ""):
        self.findings.append(Finding(severity, module, message, cis, fstec))

    def print_console(self):
        print("\n" + "=" * 60)
        print("  LinSec — Linux Security Auditor")
        print("=" * 60)

        total = len(self.findings)
        oks = sum(1 for f in self.findings if f.severity == 'OK')
        issues = total - oks
        print("\n" + "-" * 60)
        print(f"Всего проверок: {total}  |  OK: {oks}  |  Проблем: {issues}")
        print("-" * 60 + "\n")

    def to_json(self, filepath: str):
        data = []
        for f in self.findings:
            data.append({
                'severity': f.severity,
                'module': f.module,
                'cis': f.cis if f.cis else "—",
                'fstec': f.fstec if f.fstec else "—",
                'message': f.message
            })
        report = {
            'tool': 'LinSec',
            'timestamp': datetime.now().isoformat(),
            'total': len(self.findings),
            'findings': data
        }
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"[*] JSON-отчёт сохранён: {filepath}")

    def to_html(self, filepath: str):
        rows = ""
        for f in self.findings:
            cis_val = f.cis if f.cis else "—"
            fstec_val = f.fstec if f.fstec else "—"
            rows += f"<tr class='{f.severity}'><td>{f.severity}</td><td>{f.module}</td><td>{cis_val}</td><td>{fstec_val}</td><td>{f.message}</td></tr>\n"

        html = f"""<!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <title>LinSec Audit Report — Московский Политех</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #f0f0f0;
            color: #222;
            min-height: 100vh;
        }}
        .header {{
            background: #fff;
            border-bottom: 3px solid #000;
            padding: 24px 40px;
            display: flex;
            align-items: center;
            gap: 36px;
        }}
        .header img {{
            height: 72px;
        }}
        .header .title-block {{
            flex: 1;
        }}
        .header h1 {{
            font-size: 26px;
            font-weight: 700;
            color: #000;
            margin: 0;
        }}
        .header .subtitle {{
            font-size: 15px;
            color: #555;
            margin-top: 6px;
        }}
        .header .author {{
            text-align: right;
            font-size: 15px;
            color: #333;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1300px;
            margin: 0 auto;
            padding: 36px 48px;
        }}
        .info-bar {{
            background: #fff;
            border: 1px solid #ddd;
            border-radius: 6px;
            padding: 18px 24px;
            margin-bottom: 28px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 16px;
            color: #444;
        }}
        .info-bar .stat {{
            font-weight: 600;
        }}
        .info-bar .stat.ok {{ color: #2e7d32; }}
        .info-bar .stat.issues {{ color: #c62828; }}
        table {{
            border-collapse: collapse;
            width: 100%;
            background: #fff;
            border-radius: 6px;
            overflow: hidden;
            box-shadow: 0 1px 4px rgba(0,0,0,0.08);
        }}
        th {{
            background: #1a1a1a;
            color: #fff;
            padding: 14px 16px;
            text-align: left;
            font-size: 15px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        td {{
            padding: 12px 16px;
            border-bottom: 1px solid #e0e0e0;
            font-size: 15px;
        }}
        tr:last-child td {{
            border-bottom: none;
        }}
        .OK {{ background: #e8f5e9; }}
        .LOW {{ background: #e8eaf6; }}
        .MEDIUM {{ background: #fff8e1; }}
        .HIGH {{ background: #fbe9e7; }}
        .CRITICAL {{ background: #ffebee; }}
        .footer {{
            text-align: center;
            padding: 20px;
            font-size: 13px;
            color: #999;
            margin-top: 30px;
        }}
    </style>
    </head>
    <body>

    <div class="header">
        <img src="mospoly-logo.svg" alt="Московский Политех" onerror="this.style.display='none'">
        <div class="title-block">
            <h1>LinSec — Linux Security Auditor</h1>
            <div class="subtitle">Курсовая работа &bull; Безопасность операционных систем Linux &bull; 2026</div>
        </div>
        <div class="author">
            <strong>{self._get_author_name()}</strong><br>
            {self._get_author_group()}<br>
            Московский Политех
        </div>
    </div>

    <div class="container">
        <div class="info-bar">
            <span>Сформирован: <strong>{datetime.now().strftime('%d.%m.%Y, %H:%M:%S')}</strong></span>
            <span>Всего проверок: <strong>{len(self.findings)}</strong></span>
            <span class="stat ok">ОК: <strong>{sum(1 for f in self.findings if f.severity == 'OK')}</strong></span>
            <span class="stat issues">Проблем: <strong>{sum(1 for f in self.findings if f.severity != 'OK')}</strong></span>
        </div>

        <table>
            <tr><th>Severity</th><th>Module</th><th>CIS</th><th>ФСТЭК</th><th>Message</th></tr>
            {rows}
        </table>
    </div>

    </body>
    </html>"""
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"[*] HTML-отчёт сохранён: {filepath}")

    def _get_author_name(self):
        return "Сафонов А.О."

    def _get_author_group(self):
        return "Группа 241-352"