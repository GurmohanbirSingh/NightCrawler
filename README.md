# NightCrawler

NightCrawler is an AI-assisted web vulnerability scanner for **authorized security testing**. It crawls a target application, discovers HTML forms and query-parameter endpoints, probes a small set of common vulnerability classes, sends captured security responses to Gemini for verification, and produces HTML/JSON reports with optional PDF output.

> **Authorization notice:** Only scan systems you own or have explicit permission to test.

## Features

- Breadth-first same-domain crawler
- HTML form and query-parameter discovery, including non-HTML/API responses
- SQL injection probes
- Reflected XSS probes
- Path traversal probes
- Sensitive-file exposure checks
- Basic authentication-bypass probes when credential fields are discovered
- HTTP security-header checks
- Gemini-assisted verification of captured security responses and executive summary
- Differential request analysis with baseline status, response length, timing, redirects, and cookie-state isolation
- GET query-parameter injection that replaces existing values instead of appending duplicates
- HTML and JSON reporting
- Optional PDF generation through `wkhtmltopdf`
- Local automated regression tests

## Project structure

```text
NightCrawler/
├── main.py
├── requirements.txt
├── .env.example
├── .gitignore
├── modules/
│   ├── __init__.py
│   ├── crawler.py
│   ├── attacker.py
│   ├── ai_brain.py
│   └── reporter.py
├── payloads/
│   ├── sqli.txt
│   ├── xss.txt
│   ├── traversal.txt
│   └── sensitive.txt
├── tests/
│   └── test_core.py
└── sample_reports/
```

## Setup

Python 3.10+ is recommended.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Set `GEMINI_API_KEY` in `.env`. `GEMINI_MODEL` is optional and defaults to `gemini-3.8-flash`. The release uses the Gemini API directly over HTTPS, so no separate Google SDK package is required.

For PDF reports, install `wkhtmltopdf`. HTML and JSON reports work without it, and `--no-pdf` disables PDF generation explicitly.

## Run

```bash
python3 main.py --target http://127.0.0.1:8000 --no-pdf
```

Optional authentication:

```bash
python3 main.py \
  --target http://127.0.0.1:8000 \
  --login http://127.0.0.1:8000/login \
  --user admin \
  --pass password \
  --no-pdf
```

Reports are written to `sample_reports/` by default. Use `--output reports` to choose another directory.

## Tests

The regression suite does not require a live target or a live Gemini API key. It uses a local in-process HTTP server and mocked Gemini HTTP responses.

```bash
python -m unittest discover -s tests -v
python -m compileall -q main.py modules tests
```

## Security and limitations

NightCrawler is an automated security-testing aid, not a substitute for a full manual penetration test. DOM-only issues, business-logic vulnerabilities, complex multi-step authentication, and vulnerabilities that require browser execution may need separate manual testing.

Security responses are deliberately not discarded by keyword, response length, status code, or payload reflection before AI analysis. This reduces false negatives from blind SQL injection, timing-based behavior, encoded XSS, traversal variants, and authentication responses.

Keep your real Gemini key in `.env` only. Never commit `.env` or any real API key to the public repository.
