"""
NightCrawler - crawler.py
Discovers pages, forms, URL-parameter endpoints, and HTTP security-header issues.
"""

import time
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import requests
from bs4 import BeautifulSoup


class Crawler:
    def __init__(self, base_url, max_pages=100, delay=0.3, timeout=8):
        parsed_base = urlparse(base_url)
        if parsed_base.scheme not in {"http", "https"} or not parsed_base.netloc:
            raise ValueError("base_url must be a valid http:// or https:// URL")

        self.base_url = base_url.rstrip("/")
        self.base_domain = parsed_base.netloc.lower()
        self.max_pages = max(1, max_pages)
        self.delay = max(0.0, delay)
        self.timeout = max(1, timeout)
        self.visited = set()
        self.endpoints = []
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "NightCrawler/1.0 (Security Scanner - Authorized Use Only)"
            }
        )

    def login(self, login_url, credentials):
        """Optional: log in before crawling authenticated pages."""
        if not self._is_same_domain(login_url):
            print(f"  [-] Login URL is outside the target domain: {login_url}")
            return False

        try:
            resp = self.session.post(
                login_url,
                data=credentials,
                timeout=self.timeout,
                allow_redirects=True,
            )
            if resp.ok:
                print(f"  [+] Login request accepted via {login_url}")
                return True
            print(f"  [-] Login rejected with HTTP {resp.status_code}")
        except requests.exceptions.RequestException as exc:
            print(f"  [-] Login failed: {exc}")
        return False

    def _is_same_domain(self, url):
        parsed = urlparse(url)
        return (
            parsed.scheme in {"http", "https"}
            and parsed.netloc.lower() == self.base_domain
        )

    def _normalize(self, url):
        """
        Normalize URLs for crawl deduplication.

        Query parameter names are retained while their values are intentionally
        ignored so dynamic IDs do not create an unbounded crawl.
        """
        parsed = urlparse(url)
        path = parsed.path or "/"
        params = parse_qs(parsed.query, keep_blank_values=True)
        query_keys = sorted(params.keys())
        query = urlencode([(key, "") for key in query_keys], doseq=True)
        normalized = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}"
        return f"{normalized}?{query}" if query else normalized

    def _extract_forms(self, url, soup):
        """Extract same-domain forms and their input fields."""
        forms = []

        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").lower()
            full_action = urljoin(url, action) if action else url

            if not self._is_same_domain(full_action):
                continue

            inputs = {}
            for tag in form.find_all(["input", "textarea", "select"]):
                name = tag.get("name")
                if not name or tag.has_attr("disabled"):
                    continue

                input_type = tag.get("type", "text").lower()
                if input_type in {"submit", "button", "image", "reset"}:
                    continue

                if tag.name == "select":
                    selected = tag.find("option", selected=True)
                    first_option = tag.find("option")
                    option = selected or first_option
                    value = option.get("value", option.text) if option else ""
                elif tag.name == "textarea":
                    value = tag.text
                else:
                    value = tag.get("value", "test")

                inputs[name] = value

            if inputs:
                forms.append(
                    {
                        "type": "form",
                        "url": full_action,
                        "method": method,
                        "inputs": inputs,
                        "source_page": url,
                    }
                )

        return forms

    def _extract_links(self, url, soup):
        """Extract all same-domain HTTP(S) links from a page."""
        links = []

        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if (
                not href
                or href.startswith("#")
                or href.startswith("mailto:")
                or href.startswith("javascript:")
            ):
                continue

            full = urljoin(url, href)
            if self._is_same_domain(full):
                links.append(full)

        return links

    def _extract_url_params(self, url):
        """Represent a URL with query parameters as a GET endpoint."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return None

        return {
            "type": "url_param",
            "url": url,
            "method": "get",
            "inputs": {
                key: values[0] if values else ""
                for key, values in params.items()
            },
            "source_page": url,
        }

    def crawl(self):
        """Main crawl loop — BFS across the target application."""
        queue = [self.base_url]
        print(f"\n[*] Starting crawl on {self.base_url}")
        print(f"[*] Max pages: {self.max_pages} | Delay: {self.delay}s\n")

        while queue and len(self.visited) < self.max_pages:
            url = queue.pop(0)
            normalized = self._normalize(url)

            if normalized in self.visited:
                continue

            self.visited.add(normalized)

            try:
                resp = self.session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=True,
                )
                print(f"  [crawl] {resp.status_code} {url}")

                # Query-parameter endpoints must be recorded regardless of the
                # response content type. API/JSON/text endpoints are common and
                # can still be vulnerable even though they are not crawlable HTML.
                param_ep = self._extract_url_params(url)
                if param_ep:
                    self.endpoints.append(param_ep)

                if "text/html" not in resp.headers.get("Content-Type", "").lower():
                    continue

                soup = BeautifulSoup(resp.text, "html.parser")
                self.endpoints.extend(self._extract_forms(url, soup))

                for link in self._extract_links(url, soup):
                    if self._normalize(link) not in self.visited:
                        queue.append(link)

                time.sleep(self.delay)

            except requests.exceptions.ConnectionError:
                print(f"  [-] Connection refused: {url}")
            except requests.exceptions.Timeout:
                print(f"  [-] Timeout: {url}")
            except requests.exceptions.RequestException as exc:
                print(f"  [-] Request error on {url}: {exc}")
            except Exception as exc:
                print(f"  [-] Error on {url}: {exc}")

        seen = set()
        unique = []

        for endpoint in self.endpoints:
            key = (
                f"{self._normalize(endpoint['url'])}:"
                f"{endpoint['method'].lower()}:"
                f"{','.join(sorted(endpoint['inputs'].keys()))}"
            )
            if key not in seen:
                seen.add(key)
                unique.append(endpoint)

        self.endpoints = unique

        print(
            f"\n[*] Crawl complete: {len(self.visited)} pages, "
            f"{len(self.endpoints)} endpoints found\n"
        )
        return self.endpoints

    def check_headers(self):
        """Check the target's HTTP response headers for security misconfigurations."""
        try:
            resp = self.session.get(
                self.base_url,
                timeout=self.timeout,
                allow_redirects=False,
            )
            headers = resp.headers
            issues = []

            security_headers = {
                "Content-Security-Policy": "Missing CSP header — XSS protection weakened",
                "X-Frame-Options": "Missing X-Frame-Options — clickjacking possible",
                "X-Content-Type-Options": "Missing X-Content-Type-Options — MIME sniffing risk",
                "Referrer-Policy": "Missing Referrer-Policy — Referrer leakage risk",
                "Permissions-Policy": "Missing Permissions-Policy header",
            }

            if urlparse(self.base_url).scheme == "https":
                security_headers["Strict-Transport-Security"] = (
                    "Missing HSTS — SSL stripping risk"
                )

            for header, issue in security_headers.items():
                if header not in headers:
                    issues.append(
                        {
                            "type": "missing_header",
                            "header": header,
                            "issue": issue,
                            "url": self.base_url,
                        }
                    )

            disclosure_headers = [
                "Server",
                "X-Powered-By",
                "X-AspNet-Version",
                "X-Generator",
            ]
            for header in disclosure_headers:
                if header in headers:
                    issues.append(
                        {
                            "type": "info_disclosure_header",
                            "header": header,
                            "value": headers[header],
                            "issue": (
                                f"Server reveals technology via {header}: "
                                f"{headers[header]}"
                            ),
                            "url": self.base_url,
                        }
                    )

            return issues

        except requests.exceptions.RequestException as exc:
            print(f"  [-] Header check failed: {exc}")
            return []
