#!/usr/bin/env python3
"""
NightCrawler v1.0 — AI-Powered Web Vulnerability Hunter
Project: NightCrawler

LEGAL DISCLAIMER:
This tool is for authorized security testing ONLY.
Only use against systems you own or have explicit written permission to test.
Unauthorized use is illegal under the Computer Fraud and Abuse Act and equivalent laws.
"""

import argparse
import os
import sys
import time

from dotenv import load_dotenv

load_dotenv()

from modules.ai_brain import AIBrain
from modules.attacker import Attacker
from modules.crawler import Crawler
from modules.reporter import Reporter


BANNER = """
███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗ ██████╗██████╗  █████╗ ██╗    ██╗██╗     ███████╗██████╗ 
████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██║    ██║██║     ██╔════╝██╔══██╗
██╔██╗ ██║██║██║  ███╗███████║   ██║   ██║     ██████╔╝███████║██║ █╗ ██║██║     █████╗  ██████╔╝
██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██║     ██╔══██╗██╔══██║██║███╗██║██║     ██╔══╝  ██╔══██╗
██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗███████╗██║  ██║
╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝
                        AI-Powered Web Vulnerability Hunter v1.0
              [ Only use against systems you own or have permission to test ]
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="NightCrawler — AI-Powered Web Vulnerability Hunter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py --target http://localhost
  python3 main.py --target http://127.0.0.1:8000 --max-pages 50
  python3 main.py --target http://testphp.vulnweb.com --delay 0.5
  python3 main.py --target http://localhost --login http://localhost/login --user admin --pass password
        """,
    )
    parser.add_argument("--target", required=True, help="Target URL to scan")
    parser.add_argument("--max-pages", type=int, default=80, help="Max pages to crawl (default: 80)")
    parser.add_argument("--delay", type=float, default=0.2, help="Delay between requests in seconds (default: 0.2)")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout in seconds (default: 8)")
    parser.add_argument("--login", default=None, help="Login URL (if target requires auth)")
    parser.add_argument("--user", default=None, help="Username for login")
    parser.add_argument("--pass", dest="password", default=None, help="Password for login")
    parser.add_argument("--output", default=None, help="Output directory for reports")
    parser.add_argument("--no-pdf", action="store_true", help="Skip PDF generation")
    return parser.parse_args()


def print_phase(num, title):
    print(f"\n{'=' * 60}")
    print(f"  PHASE {num}: {title}")
    print(f"{'=' * 60}\n")


def validate_args(args):
    if args.max_pages < 1:
        raise ValueError("--max-pages must be at least 1")
    if args.delay < 0:
        raise ValueError("--delay cannot be negative")
    if args.timeout < 1:
        raise ValueError("--timeout must be at least 1 second")
    if not args.target.lower().startswith(("http://", "https://")):
        raise ValueError("--target must start with http:// or https://")
    if args.login and not (args.user and args.password is not None):
        raise ValueError("--login requires --user and --pass")


def main():
    print(BANNER)
    args = parse_args()

    try:
        validate_args(args)
    except ValueError as exc:
        print(f"[!] ERROR: {exc}")
        return 2

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("[!] ERROR: GEMINI_API_KEY not found.")
        print("[!] Add it to your .env file: GEMINI_API_KEY=your_key_here")
        return 1

    ai_model = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
    print(f"[*] Target: {args.target}")
    print(f"[*] Max pages: {args.max_pages} | Delay: {args.delay}s | Timeout: {args.timeout}s")
    print("[*] API key: configured")
    print(f"[*] AI model: {ai_model}")

    start_time = time.time()

    try:
        print_phase(1, "CRAWLING TARGET")
        crawler = Crawler(
            base_url=args.target,
            max_pages=args.max_pages,
            delay=args.delay,
            timeout=args.timeout,
        )

        if args.login and args.user and args.password is not None:
            print(f"[*] Attempting login at {args.login}...")
            crawler.login(
                args.login,
                {"username": args.user, "password": args.password},
            )

        endpoints = crawler.crawl()
        header_issues = crawler.check_headers()
        print(f"[*] Header check: {len(header_issues)} misconfigurations found")

        if not endpoints and not header_issues:
            print("[!] No endpoints discovered. Check the target URL and try again.")
            return 1

        print_phase(2, "RUNNING ATTACK PAYLOADS")
        attacker = Attacker(
            session=crawler.session,
            delay=args.delay,
            timeout=args.timeout,
        )
        attack_results = attacker.run_all(endpoints, args.target)

        print_phase(3, "AI ANALYSIS (GEMINI)")
        brain = AIBrain(api_key=api_key)
        findings, summary = brain.batch_analyze(attack_results, header_issues)

        print_phase(4, "GENERATING REPORT")
        reporter = Reporter(output_dir=args.output)
        report_paths = reporter.generate(
            target=args.target,
            findings=findings,
            summary=summary,
            metadata={
                "pages_crawled": len(crawler.visited),
                "endpoints_tested": len(endpoints),
                "responses_collected": len(attack_results),
                "ai_calls": brain.call_count,
                "ai_model": ai_model,
            },
            generate_pdf=not args.no_pdf,
        )

        elapsed = round(time.time() - start_time, 1)
        severity_counts = {}
        for finding in findings:
            severity = finding.get("severity", "Low")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        print(f"\n{'=' * 60}")
        print("  NIGHTCRAWLER SCAN COMPLETE")
        print(f"{'=' * 60}")
        print(f"  Target            : {args.target}")
        print(f"  Time elapsed      : {elapsed}s")
        print(f"  Pages crawled     : {len(crawler.visited)}")
        print(f"  Endpoints tested  : {len(endpoints)}")
        print(f"  Responses analyzed: {len(attack_results)}")
        print(f"  AI calls made     : {brain.call_count}")
        print("  ── Findings ──────────────────────")
        print(f"  Critical          : {severity_counts.get('Critical', 0)}")
        print(f"  High              : {severity_counts.get('High', 0)}")
        print(f"  Medium            : {severity_counts.get('Medium', 0)}")
        print(f"  Low               : {severity_counts.get('Low', 0)}")
        print(f"  Total             : {len(findings)}")
        print("  ── Reports ───────────────────────")
        print(f"  HTML              : {report_paths['html']}")
        if report_paths.get("pdf"):
            print(f"  PDF               : {report_paths['pdf']}")
        print(f"  JSON              : {report_paths['json']}")
        print(f"{'=' * 60}\n")
        return 0

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        return 130
    except Exception as exc:
        print(f"[!] Scan failed: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
