"""
NightCrawler - reporter.py
Generates professional HTML and PDF pentest reports from findings.
"""

import datetime
import json
import os
import re
import subprocess

from jinja2 import Environment, select_autoescape


REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NightCrawler Security Report — {{ target }}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #e6edf3; }
  .cover { background: linear-gradient(135deg, #0d1117 0%, #161b22 50%, #0d1117 100%); border-bottom: 2px solid #21262d; padding: 60px 80px 50px; }
  .cover-logo { font-size: 13px; color: #7d8590; letter-spacing: 0.15em; text-transform: uppercase; margin-bottom: 40px; }
  .cover-title { font-size: 42px; font-weight: 700; color: #f0f6fc; line-height: 1.2; }
  .cover-title span { color: #ff4444; }
  .cover-subtitle { font-size: 16px; color: #7d8590; margin-top: 10px; }
  .cover-meta { display: flex; gap: 40px; margin-top: 40px; flex-wrap: wrap; }
  .cover-meta-item label { font-size: 11px; color: #7d8590; text-transform: uppercase; letter-spacing: 0.1em; display: block; margin-bottom: 4px; }
  .cover-meta-item span { font-size: 15px; color: #e6edf3; word-break: break-word; }
  .content { max-width: 960px; margin: 0 auto; padding: 50px 40px; }
  .summary-bar { display: flex; gap: 16px; margin-bottom: 40px; flex-wrap: wrap; }
  .summary-card { flex: 1; min-width: 120px; padding: 20px; border-radius: 10px; text-align: center; }
  .summary-card .num { font-size: 36px; font-weight: 700; }
  .summary-card .lbl { font-size: 12px; color: #7d8590; text-transform: uppercase; letter-spacing: 0.08em; margin-top: 4px; }
  .card-critical { background: #2d0a0a; border: 1px solid #ff4444; }
  .card-critical .num { color: #ff4444; }
  .card-high { background: #1f1500; border: 1px solid #e67e22; }
  .card-high .num { color: #e67e22; }
  .card-medium { background: #1a1600; border: 1px solid #f1c40f; }
  .card-medium .num { color: #f1c40f; }
  .card-low { background: #001a09; border: 1px solid #27ae60; }
  .card-low .num { color: #27ae60; }
  .card-total { background: #161b22; border: 1px solid #30363d; }
  .card-total .num { color: #e6edf3; }
  .section-title { font-size: 13px; font-weight: 600; color: #7d8590; text-transform: uppercase; letter-spacing: 0.12em; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid #21262d; }
  .exec-summary { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 24px; margin-bottom: 40px; line-height: 1.8; color: #c9d1d9; font-size: 15px; }
  .finding { border-radius: 10px; margin-bottom: 20px; overflow: hidden; }
  .finding-header { padding: 16px 20px; display: flex; align-items: center; gap: 12px; }
  .finding-body { padding: 20px; background: #161b22; border: 1px solid #30363d; border-top: none; border-radius: 0 0 10px 10px; }
  .sev-badge { padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; }
  .critical .finding-header { background: #2d0a0a; border: 1px solid #ff4444; border-bottom: none; border-radius: 10px 10px 0 0; }
  .critical .sev-badge { background: #ff4444; color: #fff; }
  .high .finding-header { background: #1f1500; border: 1px solid #e67e22; border-bottom: none; border-radius: 10px 10px 0 0; }
  .high .sev-badge { background: #e67e22; color: #fff; }
  .medium .finding-header { background: #1a1600; border: 1px solid #f1c40f; border-bottom: none; border-radius: 10px 10px 0 0; }
  .medium .sev-badge { background: #f1c40f; color: #000; }
  .low .finding-header { background: #001a09; border: 1px solid #27ae60; border-bottom: none; border-radius: 10px 10px 0 0; }
  .low .sev-badge { background: #27ae60; color: #fff; }
  .finding-title { font-size: 16px; font-weight: 600; color: #f0f6fc; }
  .finding-endpoint { font-size: 12px; color: #7d8590; font-family: monospace; margin-top: 2px; word-break: break-all; }
  .detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }
  .detail-item label { font-size: 11px; color: #7d8590; text-transform: uppercase; letter-spacing: 0.08em; display: block; margin-bottom: 4px; }
  .detail-item span { font-size: 13px; color: #c9d1d9; }
  .detail-item code { background: #0d1117; padding: 4px 8px; border-radius: 4px; font-family: monospace; font-size: 12px; color: #79c0ff; word-break: break-all; display: block; margin-top: 4px; white-space: pre-wrap; }
  .evidence-box { background: #0d1117; border: 1px solid #21262d; border-radius: 6px; padding: 12px; margin-bottom: 16px; font-size: 13px; color: #8b949e; line-height: 1.6; white-space: pre-wrap; overflow-wrap: anywhere; }
  .evidence-box strong { color: #e6edf3; display: block; margin-bottom: 4px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; }
  .fix-box { background: #0a1628; border: 1px solid #1f3a5f; border-radius: 6px; padding: 14px; font-size: 13px; color: #79c0ff; line-height: 1.7; white-space: pre-wrap; overflow-wrap: anywhere; }
  .fix-box strong { color: #58a6ff; display: block; margin-bottom: 6px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; }
  .info-table { width: 100%; border-collapse: collapse; margin-bottom: 40px; }
  .info-table th { background: #161b22; padding: 10px 14px; text-align: left; font-size: 11px; color: #7d8590; text-transform: uppercase; letter-spacing: 0.08em; border: 1px solid #30363d; }
  .info-table td { padding: 10px 14px; font-size: 13px; color: #c9d1d9; border: 1px solid #21262d; vertical-align: top; overflow-wrap: anywhere; }
  .info-table tr:nth-child(even) td { background: #0d1117; }
  .limitations { background: #111820; border: 1px solid #30363d; border-radius: 10px; padding: 18px 20px; color: #8b949e; font-size: 13px; line-height: 1.7; margin-bottom: 40px; }
  .footer { text-align: center; padding: 40px; color: #30363d; font-size: 12px; border-top: 1px solid #21262d; margin-top: 60px; }
  .no-findings { text-align: center; padding: 60px; color: #7d8590; }
  .confidence { font-size: 11px; color: #7d8590; margin-left: auto; white-space: nowrap; }
  @media (max-width: 700px) { .cover { padding: 40px 24px; } .content { padding: 30px 20px; } .detail-grid { grid-template-columns: 1fr; } .confidence { display: none; } }
</style>
</head>
<body>

<div class="cover">
  <div class="cover-logo">NightCrawler — AI-Powered Security Scanner</div>
  <div class="cover-title">Vulnerability<br>Assessment <span>Report</span></div>
  <div class="cover-subtitle">Automated Penetration Testing Analysis</div>
  <div class="cover-meta">
    <div class="cover-meta-item"><label>Target</label><span>{{ target }}</span></div>
    <div class="cover-meta-item"><label>Scan Date</label><span>{{ date }}</span></div>
    <div class="cover-meta-item"><label>Tool</label><span>NightCrawler v1.0</span></div>
    <div class="cover-meta-item"><label>AI Model</label><span>{{ ai_model }}</span></div>
  </div>
</div>

<div class="content">
  <div class="summary-bar">
    <div class="summary-card card-total"><div class="num">{{ findings|length }}</div><div class="lbl">Total Findings</div></div>
    <div class="summary-card card-critical"><div class="num">{{ findings|selectattr('severity','equalto','Critical')|list|length }}</div><div class="lbl">Critical</div></div>
    <div class="summary-card card-high"><div class="num">{{ findings|selectattr('severity','equalto','High')|list|length }}</div><div class="lbl">High</div></div>
    <div class="summary-card card-medium"><div class="num">{{ findings|selectattr('severity','equalto','Medium')|list|length }}</div><div class="lbl">Medium</div></div>
    <div class="summary-card card-low"><div class="num">{{ findings|selectattr('severity','equalto','Low')|list|length }}</div><div class="lbl">Low</div></div>
  </div>

  <div class="section-title">Executive Summary</div>
  <div class="exec-summary">{{ summary }}</div>

  <div class="section-title">Findings ({{ findings|length }})</div>
  {% if findings %}
    {% for f in findings %}
    <div class="finding {{ f.severity|lower }}">
      <div class="finding-header">
        <span class="sev-badge">{{ f.severity }}</span>
        <div>
          <div class="finding-title">{{ f.attack_type }}</div>
          <div class="finding-endpoint">{{ f.endpoint }}</div>
        </div>
        <span class="confidence">{{ f.confidence|upper }} confidence</span>
      </div>
      <div class="finding-body">
        <div class="detail-grid">
          <div class="detail-item"><label>Field / Parameter</label><span>{{ f.field }}</span></div>
          <div class="detail-item"><label>HTTP Method</label><span>{{ f.method|upper }}</span></div>
          <div class="detail-item"><label>Status Code</label><span>{{ f.status_code }}</span></div>
          <div class="detail-item"><label>Response Time</label><span>{{ f.response_time_ms if f.response_time_ms is defined else 'N/A' }} ms</span></div>
          <div class="detail-item"><label>Timing Delta vs Baseline</label><span>{{ f.response_time_delta_ms if f.response_time_delta_ms is defined else 'N/A' }} ms</span></div>
          <div class="detail-item"><label>Request URL</label><span>{{ f.request_url if f.request_url is defined else f.endpoint }}</span></div>
          <div class="detail-item"><label>Payload Used</label><code>{{ f.payload }}</code></div>
          <div class="detail-item"><label>Redirect Location</label><span>{{ f.redirect_location if f.redirect_location else 'None' }}</span></div>
        </div>
        <div class="evidence-box"><strong>Evidence</strong>{{ f.evidence }}</div>
        <div class="evidence-box"><strong>Explanation</strong>{{ f.explanation }}</div>
        <div class="fix-box"><strong>Remediation</strong>{{ f.fix }}</div>
      </div>
    </div>
    {% endfor %}
  {% else %}
    <div class="no-findings">
      <p style="font-size: 18px; margin-bottom: 8px;">No vulnerabilities detected</p>
      <p>The target passed all automated security checks included in this scan.</p>
    </div>
  {% endif %}

  <div class="section-title" style="margin-top: 50px;">Scan Metadata</div>
  <table class="info-table">
    <tr><th>Property</th><th>Value</th></tr>
    <tr><td>Target URL</td><td>{{ target }}</td></tr>
    <tr><td>Scan Date</td><td>{{ date }}</td></tr>
    <tr><td>Pages Crawled</td><td>{{ pages_crawled }}</td></tr>
    <tr><td>Endpoints Tested</td><td>{{ endpoints_tested }}</td></tr>
    <tr><td>Attack Responses Collected</td><td>{{ responses_collected }}</td></tr>
    <tr><td>AI Analysis Calls</td><td>{{ ai_calls }}</td></tr>
    <tr><td>AI Model</td><td>{{ ai_model }}</td></tr>
    <tr><td>Total Findings</td><td>{{ findings|length }}</td></tr>
    <tr><td>Scanner</td><td>NightCrawler v1.0 — AI-Powered Web Security Scanner</td></tr>
  </table>

  <div class="section-title">Scope &amp; Limitations</div>
  <div class="limitations">
    NightCrawler is an automated security-testing aid, not a guarantee that a target is secure.
    Results depend on the pages and endpoints discovered during the crawl, the supplied payload sets,
    server behavior, and AI verification. DOM-only vulnerabilities, business-logic flaws, and issues that
    require multi-step authenticated workflows may require manual testing.
  </div>

  <div class="footer">
    This report was generated by NightCrawler for authorized security testing only.<br>
    Unauthorized use against systems you do not own is illegal and unethical.<br><br>
    NightCrawler v1.0 | AI Analysis by Gemini (Google)
  </div>
</div>
</body>
</html>
"""


class Reporter:
    SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

    def __init__(self, output_dir=None):
        self.output_dir = output_dir or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "sample_reports"
        )
        os.makedirs(self.output_dir, exist_ok=True)

    def generate(self, target, findings, summary, metadata, generate_pdf=True):
        """Generate HTML and JSON reports, with optional PDF conversion."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = re.sub(r"[^A-Za-z0-9._-]+", "_", target).strip("_") or "target"
        html_path = os.path.join(
            self.output_dir, f"nightcrawler_{safe_target}_{timestamp}.html"
        )
        pdf_path = os.path.join(
            self.output_dir, f"nightcrawler_{safe_target}_{timestamp}.pdf"
        )
        json_path = os.path.join(
            self.output_dir, f"nightcrawler_{safe_target}_{timestamp}.json"
        )

        ordered_findings = sorted(
            findings,
            key=lambda finding: self.SEVERITY_ORDER.get(finding.get("severity"), 99),
        )

        env = Environment(
            autoescape=select_autoescape(enabled_extensions=("html", "xml"), default_for_string=True)
        )
        template = env.from_string(REPORT_TEMPLATE)
        html = template.render(
            target=target,
            date=datetime.datetime.now().strftime("%B %d, %Y at %H:%M"),
            findings=ordered_findings,
            summary=summary,
            pages_crawled=metadata.get("pages_crawled", "N/A"),
            endpoints_tested=metadata.get("endpoints_tested", "N/A"),
            responses_collected=metadata.get("responses_collected", "N/A"),
            ai_calls=metadata.get("ai_calls", "N/A"),
            ai_model=metadata.get("ai_model", os.getenv("GEMINI_MODEL", "gemini-3.8-flash")),
        )

        with open(html_path, "w", encoding="utf-8") as handle:
            handle.write(html)
        print(f"  [+] HTML report saved: {html_path}")

        with open(json_path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "target": target,
                    "date": datetime.datetime.now().isoformat(),
                    "summary": summary,
                    "findings": ordered_findings,
                    "metadata": metadata,
                },
                handle,
                indent=2,
                ensure_ascii=False,
            )
        print(f"  [+] JSON findings saved: {json_path}")

        pdf_generated = self._to_pdf(html_path, pdf_path) if generate_pdf else False
        if not generate_pdf:
            print("  [*] PDF generation skipped (--no-pdf)")

        return {
            "html": html_path,
            "pdf": pdf_path if pdf_generated else None,
            "json": json_path,
        }

    def _to_pdf(self, html_path, pdf_path):
        """Try converting HTML to PDF using wkhtmltopdf."""
        try:
            result = subprocess.run(
                [
                    "wkhtmltopdf",
                    "--page-size",
                    "A4",
                    "--margin-top",
                    "10mm",
                    "--margin-bottom",
                    "10mm",
                    "--margin-left",
                    "10mm",
                    "--margin-right",
                    "10mm",
                    "--encoding",
                    "UTF-8",
                    "--quiet",
                    html_path,
                    pdf_path,
                ],
                capture_output=True,
                timeout=60,
                check=False,
            )
            if result.returncode == 0 and os.path.exists(pdf_path):
                print(f"  [+] PDF report saved: {pdf_path}")
                return True

            print("  [-] wkhtmltopdf failed (install with: sudo apt install wkhtmltopdf)")
            return False
        except FileNotFoundError:
            print("  [-] wkhtmltopdf not found — HTML report only (sudo apt install wkhtmltopdf)")
            return False
        except subprocess.TimeoutExpired:
            print("  [-] PDF generation timed out")
            return False
