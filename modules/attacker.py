"""
NightCrawler - attacker.py
Executes authorized active security probes and records evidence for AI analysis.
"""

import copy
import os
import time
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import requests


def load_payloads(filename):
    """Load non-empty, non-comment payloads from the payloads directory."""
    base = os.path.join(os.path.dirname(os.path.dirname(__file__)), "payloads", filename)
    with open(base, "r", encoding="utf-8") as handle:
        return [
            line.strip()
            for line in handle
            if line.strip() and not line.lstrip().startswith("#")
        ]


class Attacker:
    def __init__(self, session=None, delay=0.2, timeout=8):
        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "NightCrawler/1.0 (Security Scanner - Authorized Use Only)"
            }
        )
        self.delay = max(0.0, delay)
        self.timeout = max(1, timeout)

        self.sqli_payloads = load_payloads("sqli.txt")
        self.xss_payloads = load_payloads("xss.txt")
        self.traversal_payloads = load_payloads("traversal.txt")
        self.sensitive_paths = load_payloads("sensitive.txt")

    @staticmethod
    def _build_get_url(url, params):
        """
        Replace targeted query parameters instead of appending duplicate keys.

        This is critical for URL-parameter endpoints: many frameworks read the
        first occurrence of a duplicate key, so requests(url, params=...) can
        otherwise leave the original benign value in control of the application.
        """
        parsed = urlsplit(url)
        replacements = {str(key): str(value) for key, value in params.items()}
        existing = parse_qsl(parsed.query, keep_blank_values=True)

        merged = []
        replaced = set()

        for key, value in existing:
            if key in replacements:
                if key not in replaced:
                    merged.append((key, replacements[key]))
                    replaced.add(key)
                # Drop duplicate occurrences of a targeted parameter.
            else:
                merged.append((key, value))

        for key, value in replacements.items():
            if key not in replaced:
                merged.append((key, value))

        return urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                urlencode(merged, doseq=True),
                parsed.fragment,
            )
        )

    @staticmethod
    def _restore_cookies(session, snapshot):
        """Restore the session cookie jar after an individual active probe."""
        session.cookies.clear()
        session.cookies.update(copy.deepcopy(snapshot))

    def _send(self, url, method, data=None, params=None):
        """Send a single supported request without hiding redirect responses."""
        method = method.lower()
        if method not in {"get", "post"}:
            print(f"  [-] Unsupported HTTP method for active testing: {method.upper()}")
            return None

        try:
            if method == "post":
                return self.session.post(
                    url,
                    data=data,
                    timeout=self.timeout,
                    allow_redirects=False,
                )

            # For GET security tests, params are merged into the URL so existing
            # query values are replaced rather than duplicated.
            request_url = self._build_get_url(url, params or {}) if params else url
            return self.session.get(
                request_url,
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.RequestException as exc:
            print(f"  [-] Request failed: {exc}")
            return None

    @staticmethod
    def _result(
        attack_type,
        endpoint,
        request_url,
        method,
        field,
        payload,
        started,
        resp,
        baseline=None,
    ):
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        body = resp.text[:1500]

        result = {
            "attack_type": attack_type,
            "endpoint": endpoint,
            "request_url": request_url,
            "method": method,
            "field": field,
            "payload": payload,
            "status_code": resp.status_code,
            "response_body": body,
            "response_headers": dict(resp.headers),
            "response_length": len(resp.text),
            "response_time_ms": elapsed_ms,
            "redirect_location": resp.headers.get("Location"),
        }

        if baseline:
            result.update(
                {
                    "baseline_status_code": baseline["status_code"],
                    "baseline_response_length": baseline["response_length"],
                    "baseline_response_time_ms": baseline["response_time_ms"],
                    "response_time_delta_ms": round(
                        elapsed_ms - baseline["response_time_ms"], 2
                    ),
                    "baseline_redirect_location": baseline.get("redirect_location"),
                }
            )

        return result

    def _baseline(self, endpoint):
        """Capture one benign response to support differential analysis."""
        url = endpoint["url"]
        method = endpoint["method"].lower()
        inputs = endpoint.get("inputs", {})
        snapshot = copy.deepcopy(self.session.cookies)

        try:
            started = time.perf_counter()
            if method == "post":
                resp = self._send(url, "post", data=inputs)
                request_url = url
            elif method == "get":
                request_url = self._build_get_url(url, inputs)
                resp = self._send(url, "get", params=inputs)
            else:
                return None

            if resp is None:
                return None

            elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
            return {
                "status_code": resp.status_code,
                "response_length": len(resp.text),
                "response_time_ms": elapsed_ms,
                "redirect_location": resp.headers.get("Location"),
                "request_url": request_url,
            }
        finally:
            self._restore_cookies(self.session, snapshot)

    def _send_payload(self, endpoint, method, injected):
        """Send an isolated payload request and return response plus request URL."""
        url = endpoint["url"]
        snapshot = copy.deepcopy(self.session.cookies)

        try:
            started = time.perf_counter()
            if method == "post":
                request_url = url
                resp = self._send(url, "post", data=injected)
            elif method == "get":
                request_url = self._build_get_url(url, injected)
                resp = self._send(url, "get", params=injected)
            else:
                return None, None, None

            return resp, request_url, started
        finally:
            # Do not let one active payload alter the authenticated session for
            # subsequent tests. Existing login cookies are restored unchanged.
            self._restore_cookies(self.session, snapshot)

    def _test_payloads(self, endpoint, payloads, attack_type):
        results = []
        method = endpoint.get("method", "get").lower()
        original_inputs = endpoint.get("inputs", {})
        baseline = self._baseline(endpoint)

        if method not in {"get", "post"}:
            return results

        for payload in payloads:
            for field in original_inputs:
                injected = dict(original_inputs)
                injected[field] = payload

                resp, request_url, started = self._send_payload(
                    endpoint,
                    method,
                    injected,
                )
                if resp is None:
                    continue

                results.append(
                    self._result(
                        attack_type,
                        endpoint["url"],
                        request_url,
                        method,
                        field,
                        payload,
                        started,
                        resp,
                        baseline=baseline,
                    )
                )
                time.sleep(self.delay)

        return results

    def test_sqli(self, endpoint):
        """Test an endpoint for SQL injection."""
        return self._test_payloads(endpoint, self.sqli_payloads, "SQL Injection")

    def test_xss(self, endpoint):
        """Test an endpoint for reflected XSS."""
        return self._test_payloads(
            endpoint,
            self.xss_payloads,
            "Cross-Site Scripting (XSS)",
        )

    def test_traversal(self, endpoint):
        """Test an endpoint for path traversal."""
        return self._test_payloads(endpoint, self.traversal_payloads, "Path Traversal")

    def test_sensitive_files(self, base_url):
        """Probe for exposed sensitive files and directories."""
        results = []
        base = base_url.rstrip("/") + "/"

        for path in self.sensitive_paths:
            parsed = urlsplit(path)
            if parsed.scheme or parsed.netloc:
                print(f"  [-] Ignoring non-path sensitive-file entry: {path}")
                continue

            # Preserve a leading '/' so absolute entries (for example /etc/passwd)
            # are tested at the target host root. Relative entries stay relative
            # to the configured scan base.
            url = urljoin(base, path)
            snapshot = copy.deepcopy(self.session.cookies)
            try:
                started = time.perf_counter()
                resp = self._send(url, "get")
                if resp is None:
                    continue

                results.append(
                    self._result(
                        "Sensitive File Exposure",
                        url,
                        url,
                        "get",
                        "path",
                        path,
                        started,
                        resp,
                    )
                )
                time.sleep(self.delay)
            finally:
                self._restore_cookies(self.session, snapshot)

        return results

    @staticmethod
    def _looks_like_auth_endpoint(inputs):
        """Return True when input names suggest a username/password login form."""
        fields = [str(field).lower() for field in inputs]
        has_identity = any(
            any(token in field for token in ("user", "email", "login"))
            for field in fields
        )
        has_secret = any(
            any(token in field for token in ("pass", "pwd", "secret"))
            for field in fields
        )
        return has_identity and has_secret

    def test_auth_bypass(self, endpoint):
        """Test for authentication bypass via common techniques."""
        results = []
        method = endpoint.get("method", "get").lower()
        if method not in {"get", "post"}:
            return results

        url = endpoint["url"]
        baseline = self._baseline(endpoint)
        bypass_payloads = [
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "admin", "password": ""},
            {"username": "' OR '1'='1'--", "password": "anything"},
            {"username": "admin'--", "password": "anything"},
            {"username": "' OR 1=1--", "password": ""},
        ]

        for payload in bypass_payloads:
            injected = {}
            for field in endpoint.get("inputs", {}):
                lowered = field.lower()
                if any(token in lowered for token in ("user", "email", "login")):
                    injected[field] = payload["username"]
                elif any(token in lowered for token in ("pass", "pwd", "secret")):
                    injected[field] = payload["password"]
                else:
                    injected[field] = "test"

            if not injected:
                continue

            resp, request_url, started = self._send_payload(
                endpoint,
                method,
                injected,
            )
            if resp is None:
                continue

            results.append(
                self._result(
                    "Authentication Bypass",
                    url,
                    request_url,
                    method,
                    "username/password",
                    str(payload),
                    started,
                    resp,
                    baseline=baseline,
                )
            )
            time.sleep(self.delay)

        return results

    def run_all(self, endpoints, base_url):
        """Run all attack modules against all discovered endpoints."""
        all_results = []

        print("[*] Phase 1: Sensitive file enumeration...")
        all_results.extend(self.test_sensitive_files(base_url))

        print(
            f"[*] Phase 2: Testing {len(endpoints)} endpoints "
            "for SQLi, XSS, Traversal, Auth Bypass..."
        )
        for index, endpoint in enumerate(endpoints):
            print(
                f"  [{index + 1}/{len(endpoints)}] "
                f"{endpoint['method'].upper()} {endpoint['url']}"
            )
            all_results.extend(self.test_sqli(endpoint))
            all_results.extend(self.test_xss(endpoint))
            all_results.extend(self.test_traversal(endpoint))

            if self._looks_like_auth_endpoint(endpoint.get("inputs", {})):
                all_results.extend(self.test_auth_bypass(endpoint))

        print(
            f"\n[*] Attack phase complete: {len(all_results)} responses collected\n"
        )
        return all_results
