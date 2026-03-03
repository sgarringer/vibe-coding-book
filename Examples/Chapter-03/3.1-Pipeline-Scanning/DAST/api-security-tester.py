#!/usr/bin/env python3
"""
Custom API Security Tester
Book Reference: Chapter 3, Section 3.1.3.2

Features:
  - SQL injection testing
  - XSS detection
  - Authentication bypass checks
  - Rate limiting validation
  - Custom test scenarios

Usage:
  # Basic scan
  python api-security-tester.py --url https://staging.yourapp.com/api

  # With authentication
  python api-security-tester.py \
    --url https://staging.yourapp.com/api \
    --token your-jwt-token

  # Scan specific endpoints from OpenAPI spec
  python api-security-tester.py \
    --url https://staging.yourapp.com/api \
    --spec openapi.json \
    --output results.json

  # Verbose output with all findings
  python api-security-tester.py \
    --url https://staging.yourapp.com/api \
    --verbose

Requirements:
  pip install requests colorama
"""

import argparse
import json
import sys
import time
import urllib.parse
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
from datetime import datetime, timezone

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Suppress SSL warnings when verify=False is used in tests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLOR_ENABLED = True
except ImportError:
    COLOR_ENABLED = False


# =============================================================================
# Data Models
# =============================================================================

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class TestStatus(str, Enum):
    PASS    = "PASS"
    FAIL    = "FAIL"
    WARNING = "WARNING"
    ERROR   = "ERROR"
    SKIP    = "SKIP"


@dataclass
class Finding:
    """Represents a single security finding."""
    test_id:     str
    title:       str
    severity:    Severity
    status:      TestStatus
    description: str
    evidence:    str        = ""
    endpoint:    str        = ""
    remediation: str        = ""
    cwe:         str        = ""
    owasp:       str        = ""


@dataclass
class TestResult:
    """Aggregated results from all security tests."""
    target_url:  str
    scan_start:  str
    scan_end:    str         = ""
    findings:    list        = field(default_factory=list)
    tests_run:   int         = 0
    tests_passed: int        = 0
    tests_failed: int        = 0

    def summary(self) -> dict:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            if f.status == TestStatus.FAIL:
                counts[f.severity.value] += 1
        return counts


# =============================================================================
# Color output helpers
# =============================================================================

def _color(text: str, color_code: str) -> str:
    if COLOR_ENABLED:
        return f"{color_code}{text}{Style.RESET_ALL}"
    return text

def red(text):    return _color(text, Fore.RED)
def yellow(text): return _color(text, Fore.YELLOW)
def green(text):  return _color(text, Fore.GREEN)
def cyan(text):   return _color(text, Fore.CYAN)
def bold(text):   return _color(text, Style.BRIGHT)


# =============================================================================
# HTTP Session Factory
# =============================================================================

def build_session(token: Optional[str] = None,
                  verify_ssl: bool = True,
                  timeout: int = 10) -> requests.Session:
    """
    Build a requests Session with retry logic and optional auth.

    Args:
        token:      Bearer token for authenticated requests
        verify_ssl: Whether to verify SSL certificates
        timeout:    Request timeout in seconds

    Returns:
        Configured requests.Session
    """
    session = requests.Session()

    # Retry on transient errors - don't retry on 4xx (those are findings)
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://",  adapter)
    session.mount("https://", adapter)

    session.verify  = verify_ssl
    session.timeout = timeout

    session.headers.update({
        "User-Agent": "APISecurityTester/1.0 (Security Testing - Authorized)",
        "Accept":     "application/json",
    })

    if token:
        session.headers["Authorization"] = f"Bearer {token}"

    return session


# =============================================================================
# Individual Security Tests
# =============================================================================

class SQLInjectionTester:
    """
    Tests API endpoints for SQL injection vulnerabilities.

    Principle: Provide Context - each finding includes the exact payload
    and endpoint so developers can reproduce and fix the issue.
    """

    # Classic SQL injection payloads
    # These are designed to trigger errors or boolean-based differences
    PAYLOADS = [
        # Error-based
        ("'",                    "single_quote"),
        ("''",                   "double_single_quote"),
        ("' OR '1'='1",          "or_true"),
        ("' OR '1'='2",          "or_false"),
        ("1' ORDER BY 1--",      "order_by"),
        ("1' ORDER BY 2--",      "order_by_2"),
        ("1 UNION SELECT NULL--","union_null"),
        # Blind boolean
        ("1 AND 1=1",            "and_true"),
        ("1 AND 1=2",            "and_false"),
        # Time-based blind (use with caution - can be slow)
        # ("1; WAITFOR DELAY '0:0:5'--", "time_delay_mssql"),
        # ("1; SELECT SLEEP(5)--",       "time_delay_mysql"),
    ]

    # Indicators of SQL errors in responses
    ERROR_SIGNATURES = [
        "sql syntax",
        "mysql_fetch",
        "ora-01756",
        "postgresql",
        "sqlite3",
        "syntax error",
        "unclosed quotation",
        "quoted string not properly terminated",
        "invalid column name",
        "column count doesn't match",
    ]

    def __init__(self, session: requests.Session, base_url: str, verbose: bool = False):
        self.session  = session
        self.base_url = base_url.rstrip('/')
        self.verbose  = verbose

    def test_endpoint(self, path: str, param: str,
                      method: str = "GET") -> list[Finding]:
        """
        Test a single endpoint parameter for SQL injection.

        Args:
            path:   API path (e.g., /api/users)
            param:  Parameter name to test (e.g., 'id', 'search')
            method: HTTP method

        Returns:
            List of Finding objects
        """
        findings = []
        url = f"{self.base_url}{path}"

        # Get baseline response for comparison
        try:
            baseline = self._make_request(method, url, {param: "1"})
        except requests.RequestException as e:
            if self.verbose:
                print(f"  ⚠️  Could not reach {url}: {e}")
            return findings

        for payload, payload_id in self.PAYLOADS:
            try:
                response = self._make_request(method, url, {param: payload})

                # Check for SQL error signatures in response body
                body_lower = response.text.lower()
                for sig in self.ERROR_SIGNATURES:
                    if sig in body_lower:
                        findings.append(Finding(
                            test_id     = f"sqli-error-{payload_id}",
                            title       = "SQL Injection - Error Based",
                            severity    = Severity.CRITICAL,
                            status      = TestStatus.FAIL,
                            description = (
                                f"SQL error signature '{sig}' found in response "
                                f"when injecting payload into parameter '{param}'."
                            ),
                            evidence    = (
                                f"Payload: {payload!r}\n"
                                f"Signature: {sig!r}\n"
                                f"Response snippet: {response.text[:200]}"
                            ),
                            endpoint    = f"{method} {url}?{param}=<payload>",
                            remediation = (
                                "Use parameterized queries or prepared statements. "
                                "Never concatenate user input into SQL strings. "
                                "See: https://owasp.org/www-community/attacks/SQL_Injection"
                            ),
                            cwe   = "CWE-89",
                            owasp = "A03:2021 - Injection",
                        ))
                        break

                # Boolean-based detection: compare true/false responses
                if payload_id in ("or_true", "or_false"):
                    true_resp  = self._make_request(method, url,
                                                    {param: "' OR '1'='1"})
                    false_resp = self._make_request(method, url,
                                                    {param: "' OR '1'='2"})

                    # Significant difference in response length suggests
                    # boolean-based SQL injection
                    len_diff = abs(len(true_resp.text) - len(false_resp.text))
                    if len_diff > 50 and true_resp.status_code != false_resp.status_code:
                        findings.append(Finding(
                            test_id     = "sqli-boolean",
                            title       = "SQL Injection - Boolean Based (Potential)",
                            severity    = Severity.HIGH,
                            status      = TestStatus.FAIL,
                            description = (
                                f"Different responses for boolean true/false payloads "
                                f"on parameter '{param}' suggest boolean-based SQL injection."
                            ),
                            evidence    = (
                                f"True payload response length:  {len(true_resp.text)}\n"
                                f"False payload response length: {len(false_resp.text)}\n"
                                f"Difference: {len_diff} bytes"
                            ),
                            endpoint    = f"{method} {url}?{param}=<payload>",
                            remediation = (
                                "Use parameterized queries. "
                                "Validate and sanitize all user inputs."
                            ),
                            cwe   = "CWE-89",
                            owasp = "A03:2021 - Injection",
                        ))
                        break

            except requests.RequestException:
                continue

        return findings

    def _make_request(self, method: str, url: str,
                      params: dict) -> requests.Response:
        if method.upper() == "GET":
            return self.session.get(url, params=params)
        return self.session.post(url, json=params)


class XSSTester:
    """
    Tests API endpoints for Cross-Site Scripting (XSS) vulnerabilities.

    Focuses on reflected XSS where user input is echoed back in the response.
    Stored XSS requires manual verification after automated detection.
    """

    PAYLOADS = [
        # Basic script injection
        ('<script>alert(1)</script>',           "basic_script"),
        ('<img src=x onerror=alert(1)>',        "img_onerror"),
        ('<svg onload=alert(1)>',               "svg_onload"),
        # Encoded variants
        ('"><script>alert(1)</script>',         "break_attr"),
        ("'><script>alert(1)</script>",         "break_single_attr"),
        # Event handlers
        ('<body onload=alert(1)>',              "body_onload"),
        ('<input autofocus onfocus=alert(1)>',  "input_onfocus"),
        # JavaScript protocol
        ('javascript:alert(1)',                 "js_protocol"),
    ]

    def __init__(self, session: requests.Session, base_url: str, verbose: bool = False):
        self.session  = session
        self.base_url = base_url.rstrip('/')
        self.verbose  = verbose

    def test_endpoint(self, path: str, param: str,
                      method: str = "GET") -> list[Finding]:
        """Test a single endpoint parameter for reflected XSS."""
        findings = []
        url = f"{self.base_url}{path}"

        for payload, payload_id in self.PAYLOADS:
            try:
                if method.upper() == "GET":
                    response = self.session.get(url, params={param: payload})
                else:
                    response = self.session.post(url, json={param: payload})

                # Check if payload is reflected unencoded in the response
                # A properly secured app would HTML-encode the output
                if payload in response.text:
                    # Verify it's actually in an HTML context (not just JSON)
                    content_type = response.headers.get("Content-Type", "")
                    context = "HTML" if "html" in content_type else "Response body"

                    findings.append(Finding(
                        test_id     = f"xss-reflected-{payload_id}",
                        title       = "Cross-Site Scripting (XSS) - Reflected",
                        severity    = Severity.HIGH,
                        status      = TestStatus.FAIL,
                        description = (
                            f"XSS payload reflected unencoded in {context} "
                            f"for parameter '{param}'."
                        ),
                        evidence    = (
                            f"Payload: {payload!r}\n"
                            f"Content-Type: {content_type}\n"
                            f"Payload found in response: Yes"
                        ),
                        endpoint    = f"{method} {url}?{param}=<payload>",
                        remediation = (
                            "Encode all user-supplied output using context-appropriate "
                            "encoding (HTML entity encoding for HTML context). "
                            "Use a Content Security Policy (CSP) header. "
                            "See: https://owasp.org/www-community/attacks/xss/"
                        ),
                        cwe   = "CWE-79",
                        owasp = "A03:2021 - Injection",
                    ))
                    # One finding per endpoint is enough
                    break

            except requests.RequestException:
                continue

        return findings


class AuthBypassTester:
    """
    Tests for authentication bypass vulnerabilities.

    Checks:
      1. Endpoints accessible without any authentication
      2. JWT manipulation (algorithm confusion, none algorithm)
      3. Horizontal privilege escalation (accessing other users' data)
      4. Vertical privilege escalation (accessing admin endpoints)
    """

    # Common admin/sensitive endpoints to probe
    SENSITIVE_PATHS = [
        "/api/admin",
        "/api/admin/users",
        "/api/admin/config",
        "/api/users",
        "/api/users/1",
        "/api/config",
        "/api/settings",
        "/api/debug",
        "/api/health/detailed",
        "/actuator",
        "/actuator/env",
        "/actuator/beans",
        "/.env",
        "/api/v1/admin",
        "/api/v2/admin",
    ]

    def __init__(self, session: requests.Session, base_url: str,
                 token: Optional[str] = None, verbose: bool = False):
        self.session  = session
        self.base_url = base_url.rstrip('/')
        self.token    = token
        self.verbose  = verbose

    def test_unauthenticated_access(self) -> list[Finding]:
        """
        Test whether sensitive endpoints are accessible without authentication.
        """
        findings = []

        # Create an unauthenticated session for comparison
        unauth_session = build_session(token=None, verify_ssl=False)

        for path in self.SENSITIVE_PATHS:
            url = f"{self.base_url}{path}"
            try:
                response = unauth_session.get(url, timeout=5)

                # 200 or 403 with body content may indicate exposure
                # 401 = properly protected
                # 404 = endpoint doesn't exist (acceptable)
                if response.status_code == 200:
                    findings.append(Finding(
                        test_id     = f"auth-bypass-unauth-{path.replace('/', '-')}",
                        title       = "Authentication Bypass - Unauthenticated Access",
                        severity    = Severity.CRITICAL,
                        status      = TestStatus.FAIL,
                        description = (
                            f"Sensitive endpoint '{path}' returned HTTP 200 "
                            f"without authentication credentials."
                        ),
                        evidence    = (
                            f"URL: {url}\n"
                            f"Status: {response.status_code}\n"
                            f"Response length: {len(response.text)} bytes\n"
                            f"Response snippet: {response.text[:200]}"
                        ),
                        endpoint    = f"GET {url}",
                        remediation = (
                            "Ensure all sensitive endpoints require authentication. "
                            "Implement authentication middleware at the router level "
                            "rather than per-endpoint to prevent accidental exposure. "
                            "See: https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication"
                        ),
                        cwe   = "CWE-306",
                        owasp = "A01:2021 - Broken Access Control",
                    ))

                elif response.status_code == 403:
                    # 403 without auth might indicate the endpoint exists
                    # but access control is enforced - this is acceptable
                    # but worth noting for inventory purposes
                    if self.verbose:
                        print(f"  ℹ️  {path} returned 403 (endpoint exists, access denied)")

            except requests.RequestException:
                # Endpoint doesn't exist or network error - not a finding
                continue

        return findings

    def test_jwt_none_algorithm(self) -> list[Finding]:
        """
        Test for JWT 'none' algorithm vulnerability.

        Some JWT libraries accept tokens signed with 'none' algorithm,
        allowing attackers to forge tokens without a valid signature.
        """
        findings = []

        if not self.token:
            return findings

        try:
            # Decode the JWT header (base64, no verification)
            import base64
            parts = self.token.split('.')
            if len(parts) != 3:
                return findings

            # Craft a token with 'none' algorithm
            # This is a well-known attack - see CVE-2015-9235
            none_header  = base64.urlsafe_b64encode(
                b'{"alg":"none","typ":"JWT"}'
            ).rstrip(b'=').decode()

            # Keep the original payload, remove signature
            none_token = f"{none_header}.{parts[1]}."

            # Test with none algorithm token
            test_session = build_session(token=none_token, verify_ssl=False)
            response = test_session.get(f"{self.base_url}/api/users/me",
                                        timeout=5)

            if response.status_code == 200:
                findings.append(Finding(
                    test_id     = "auth-jwt-none-algorithm",
                    title       = "JWT None Algorithm Vulnerability",
                    severity    = Severity.CRITICAL,
                    status      = TestStatus.FAIL,
                    description = (
                        "The API accepted a JWT token with 'none' algorithm, "
                        "allowing authentication bypass without a valid signature."
                    ),
                    evidence    = (
                        f"Forged token accepted: {none_token[:50]}...\n"
                        f"Response status: {response.status_code}"
                    ),
                    endpoint    = "GET /api/users/me",
                    remediation = (
                        "Explicitly specify allowed algorithms when validating JWTs. "
                        "Never accept 'none' as a valid algorithm. "
                        "Example (PyJWT): jwt.decode(token, key, algorithms=['HS256'])"
                    ),
                    cwe   = "CWE-347",
                    owasp = "A02:2021 - Cryptographic Failures",
                ))

        except Exception:
            pass

        return findings

    def test_horizontal_privilege_escalation(self) -> list[Finding]:
        """
        Test for horizontal privilege escalation (IDOR).

        Checks whether an authenticated user can access another user's data
        by manipulating resource IDs.
        """
        findings = []

        if not self.token:
            return findings

        # Get current user's ID
        try:
            me_response = self.session.get(
                f"{self.base_url}/api/users/me", timeout=5
            )
            if me_response.status_code != 200:
                return findings

            current_user = me_response.json()
            current_id   = current_user.get('id') or current_user.get('user_id')

            if not current_id:
                return findings

            # Try to access adjacent user IDs
            test_ids = [
                int(current_id) - 1,
                int(current_id) + 1,
                1,  # First user (often admin)
            ]

            for test_id in test_ids:
                if test_id <= 0 or test_id == int(current_id):
                    continue

                response = self.session.get(
                    f"{self.base_url}/api/users/{test_id}", timeout=5
                )

                if response.status_code == 200:
                    findings.append(Finding(
                        test_id     = f"auth-idor-user-{test_id}",
                        title       = "Insecure Direct Object Reference (IDOR)",
                        severity    = Severity.HIGH,
                        status      = TestStatus.FAIL,
                        description = (
                            f"User {current_id} can access data for user {test_id} "
                            f"by manipulating the user ID in the URL."
                        ),
                        evidence    = (
                            f"Current user ID: {current_id}\n"
                            f"Accessed user ID: {test_id}\n"
                            f"Response status: {response.status_code}\n"
                            f"Response snippet: {response.text[:200]}"
                        ),
                        endpoint    = f"GET /api/users/{test_id}",
                        remediation = (
                            "Implement object-level authorization checks. "
                            "Verify the requesting user owns or has permission "
                            "to access the requested resource. "
                            "Consider using UUIDs instead of sequential IDs. "
                            "See: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
                        ),
                        cwe   = "CWE-639",
                        owasp = "A01:2021 - Broken Access Control",
                    ))

        except (requests.RequestException, ValueError, KeyError):
            pass

        return findings


class RateLimitTester:
    """
    Tests whether API endpoints implement rate limiting.

    Rate limiting is essential for:
      - Preventing brute force attacks on authentication endpoints
      - Protecting against denial of service
      - Preventing credential stuffing
    """

    # Endpoints that MUST have rate limiting
    CRITICAL_ENDPOINTS = [
        ("/api/auth/login",          "POST", "Authentication endpoint"),
        ("/api/auth/register",       "POST", "Registration endpoint"),
        ("/api/auth/forgot-password","POST", "Password reset endpoint"),
        ("/api/auth/reset-password", "POST", "Password reset endpoint"),
        ("/api/auth/verify-otp",     "POST", "OTP verification endpoint"),
    ]

    def __init__(self, session: requests.Session, base_url: str,
                 verbose: bool = False):
        self.session  = session
        self.base_url = base_url.rstrip('/')
        self.verbose  = verbose

    def test_rate_limiting(self, requests_count: int = 20,
                           threshold: int = 15) -> list[Finding]:
        """
        Test rate limiting by sending rapid repeated requests.

        Args:
            requests_count: Number of requests to send
            threshold:      Number of successful requests before flagging

        Returns:
            List of Finding objects
        """
        findings = []

        for path, method, description in self.CRITICAL_ENDPOINTS:
            url = f"{self.base_url}{path}"
            success_count = 0
            rate_limited  = False

            if self.verbose:
                print(f"  Testing rate limiting: {method} {path}")

            for i in range(requests_count):
                try:
                    if method == "POST":
                        # Send invalid credentials - we're testing rate limiting,
                        # not trying to authenticate
                        response = self.session.post(url, json={
                            "username": f"ratelimit_test_{i}@test.com",
                            "password": "invalid_password_for_rate_limit_test",
                        }, timeout=5)
                    else:
                        response = self.session.get(url, timeout=5)

                    # 429 = Too Many Requests (proper rate limiting)
                    if response.status_code == 429:
                        rate_limited = True
                        if self.verbose:
                            print(f"    ✅ Rate limited after {i+1} requests")
                        break

                    # Count non-404 responses as "successful" requests
                    # (even 401/403 means the endpoint processed the request)
                    if response.status_code != 404:
                        success_count += 1

                except requests.RequestException:
                    break

                # Small delay to avoid overwhelming the server
                time.sleep(0.1)

            # Flag if we sent many requests without being rate limited
            if not rate_limited and success_count >= threshold:
                findings.append(Finding(
                    test_id     = f"rate-limit-missing-{path.replace('/', '-')}",
                    title       = "Missing Rate Limiting",
                    severity    = Severity.MEDIUM,
                    status      = TestStatus.FAIL,
                    description = (
                        f"{description} at '{path}' does not appear to implement "
                        f"rate limiting. {success_count} requests were processed "
                        f"without receiving HTTP 429."
                    ),
                    evidence    = (
                        f"Requests sent: {requests_count}\n"
                        f"Requests processed: {success_count}\n"
                        f"Rate limit triggered: No\n"
                        f"Expected: HTTP 429 after ~{threshold} requests"
                    ),
                    endpoint    = f"{method} {url}",
                    remediation = (
                        "Implement rate limiting on all authentication endpoints. "
                        "Recommended limits:\n"
                        "  - Login: 5 attempts per minute per IP\n"
                        "  - Password reset: 3 attempts per hour per email\n"
                        "  - OTP verification: 5 attempts per OTP\n"
                        "Use libraries like express-rate-limit (Node.js), "
                        "django-ratelimit (Python), or API gateway rate limiting."
                    ),
                    cwe   = "CWE-307",
                    owasp = "A07:2021 - Identification and Authentication Failures",
                ))

        return findings


class SecurityHeadersTester:
    """
    Tests for presence and correctness of security HTTP headers.

    Security headers are a low-effort, high-impact defense layer.
    Missing headers are quick wins for attackers.
    """

    # Required headers with expected values/patterns
    REQUIRED_HEADERS = {
        "X-Content-Type-Options": {
            "expected": "nosniff",
            "severity": Severity.MEDIUM,
            "description": "Prevents MIME type sniffing attacks",
            "remediation": "Add header: X-Content-Type-Options: nosniff",
        },
        "X-Frame-Options": {
            "expected": ["DENY", "SAMEORIGIN"],
            "severity": Severity.MEDIUM,
            "description": "Prevents clickjacking attacks",
            "remediation": "Add header: X-Frame-Options: DENY",
        },
        "Strict-Transport-Security": {
            "expected": "max-age=",
            "severity": Severity.HIGH,
            "description": "Enforces HTTPS connections",
            "remediation": (
                "Add header: Strict-Transport-Security: "
                "max-age=31536000; includeSubDomains; preload"
            ),
        },
        "Content-Security-Policy": {
            "expected": None,   # Any value is better than none
            "severity": Severity.MEDIUM,
            "description": "Prevents XSS and data injection attacks",
            "remediation": (
                "Add a Content-Security-Policy header. "
                "Start with: Content-Security-Policy: default-src 'self'"
            ),
        },
        "X-XSS-Protection": {
            "expected": "1; mode=block",
            "severity": Severity.LOW,
            "description": "Enables browser XSS filter (legacy browsers)",
            "remediation": "Add header: X-XSS-Protection: 1; mode=block",
        },
        "Referrer-Policy": {
            "expected": None,
            "severity": Severity.LOW,
            "description": "Controls referrer information in requests",
            "remediation": (
                "Add header: Referrer-Policy: strict-origin-when-cross-origin"
            ),
        },
        "Permissions-Policy": {
            "expected": None,
            "severity": Severity.LOW,
            "description": "Controls browser feature access",
            "remediation": (
                "Add header: Permissions-Policy: "
                "geolocation=(), microphone=(), camera=()"
            ),
        },
    }

    # Headers that should NOT be present (information disclosure)
    FORBIDDEN_HEADERS = {
        "Server": {
            "severity": Severity.LOW,
            "description": "Exposes server software and version",
            "remediation": "Remove or obscure the Server header",
        },
        "X-Powered-By": {
            "severity": Severity.LOW,
            "description": "Exposes application framework and version",
            "remediation": "Remove the X-Powered-By header",
        },
        "X-AspNet-Version": {
            "severity": Severity.LOW,
            "description": "Exposes ASP.NET version",
            "remediation": "Remove the X-AspNet-Version header",
        },
        "X-AspNetMvc-Version": {
            "severity": Severity.LOW,
            "description": "Exposes ASP.NET MVC version",
            "remediation": "Remove the X-AspNetMvc-Version header",
        },
    }

    def __init__(self, session: requests.Session, base_url: str,
                 verbose: bool = False):
        self.session  = session
        self.base_url = base_url.rstrip('/')
        self.verbose  = verbose

    def test_security_headers(self) -> list[Finding]:
        """
        Test the root URL for security header presence and correctness.

        Returns:
            List of Finding objects for missing or misconfigured headers
        """
        findings = []

        try:
            response = self.session.get(self.base_url, timeout=10)
        except requests.RequestException as e:
            if self.verbose:
                print(f"  ⚠️  Could not reach {self.base_url}: {e}")
            return findings

        response_headers = {k.lower(): v for k, v in response.headers.items()}

        # -----------------------------------------------------------------------
        # Check for required headers
        # -----------------------------------------------------------------------
        for header_name, config in self.REQUIRED_HEADERS.items():
            header_lower = header_name.lower()
            actual_value = response_headers.get(header_lower)

            if actual_value is None:
                findings.append(Finding(
                    test_id     = f"headers-missing-{header_lower}",
                    title       = f"Missing Security Header: {header_name}",
                    severity    = config["severity"],
                    status      = TestStatus.FAIL,
                    description = (
                        f"The '{header_name}' header is missing from the response. "
                        f"{config['description']}."
                    ),
                    evidence    = (
                        f"URL: {self.base_url}\n"
                        f"Header '{header_name}': Not present"
                    ),
                    endpoint    = f"GET {self.base_url}",
                    remediation = config["remediation"],
                    cwe         = "CWE-693",
                    owasp       = "A05:2021 - Security Misconfiguration",
                ))

            elif config["expected"] is not None:
                # Validate the header value
                expected = config["expected"]
                if isinstance(expected, list):
                    # Header must match one of the expected values
                    if not any(e.lower() in actual_value.lower()
                               for e in expected):
                        findings.append(Finding(
                            test_id     = f"headers-invalid-{header_lower}",
                            title       = f"Misconfigured Security Header: {header_name}",
                            severity    = config["severity"],
                            status      = TestStatus.FAIL,
                            description = (
                                f"The '{header_name}' header has an unexpected value."
                            ),
                            evidence    = (
                                f"Actual:   {actual_value}\n"
                                f"Expected: one of {expected}"
                            ),
                            endpoint    = f"GET {self.base_url}",
                            remediation = config["remediation"],
                            cwe         = "CWE-693",
                            owasp       = "A05:2021 - Security Misconfiguration",
                        ))
                elif expected.lower() not in actual_value.lower():
                    findings.append(Finding(
                        test_id     = f"headers-invalid-{header_lower}",
                        title       = f"Misconfigured Security Header: {header_name}",
                        severity    = config["severity"],
                        status      = TestStatus.FAIL,
                        description = (
                            f"The '{header_name}' header has an unexpected value."
                        ),
                        evidence    = (
                            f"Actual:   {actual_value}\n"
                            f"Expected: contains '{expected}'"
                        ),
                        endpoint    = f"GET {self.base_url}",
                        remediation = config["remediation"],
                        cwe         = "CWE-693",
                        owasp       = "A05:2021 - Security Misconfiguration",
                    ))

        # -----------------------------------------------------------------------
        # Check for forbidden headers (information disclosure)
        # -----------------------------------------------------------------------
        for header_name, config in self.FORBIDDEN_HEADERS.items():
            header_lower = header_name.lower()
            actual_value = response_headers.get(header_lower)

            if actual_value is not None:
                findings.append(Finding(
                    test_id     = f"headers-exposed-{header_lower}",
                    title       = f"Information Disclosure via Header: {header_name}",
                    severity    = config["severity"],
                    status      = TestStatus.FAIL,
                    description = (
                        f"The '{header_name}' header is present and may expose "
                        f"sensitive server information. {config['description']}."
                    ),
                    evidence    = (
                        f"Header '{header_name}': {actual_value}"
                    ),
                    endpoint    = f"GET {self.base_url}",
                    remediation = config["remediation"],
                    cwe         = "CWE-200",
                    owasp       = "A05:2021 - Security Misconfiguration",
                ))

        return findings


class SensitiveDataExposureTester:
    """
    Tests for sensitive data exposure in API responses.

    Checks for:
      - Passwords or secrets in responses
      - Excessive data exposure (returning more fields than needed)
      - Sensitive data in error messages
      - Stack traces in error responses
    """

    # Patterns that should never appear in API responses
    SENSITIVE_PATTERNS = [
        ("password",        Severity.CRITICAL, "Password field in response"),
        ("passwd",          Severity.CRITICAL, "Password field in response"),
        ("secret",          Severity.HIGH,     "Secret field in response"),
        ("private_key",     Severity.CRITICAL, "Private key in response"),
        ("api_key",         Severity.HIGH,     "API key in response"),
        ("access_token",    Severity.HIGH,     "Access token in response"),
        ("credit_card",     Severity.CRITICAL, "Credit card data in response"),
        ("ssn",             Severity.CRITICAL, "Social security number in response"),
        ("stack trace",     Severity.MEDIUM,   "Stack trace in error response"),
        ("traceback",       Severity.MEDIUM,   "Stack trace in error response"),
        ("at line",         Severity.LOW,      "Possible stack trace in response"),
        ("SQLException",    Severity.HIGH,     "SQL error details exposed"),
        ("NullPointerException", Severity.MEDIUM, "Java exception details exposed"),
    ]

    # Endpoints likely to return user data
    USER_DATA_ENDPOINTS = [
        "/api/users/me",
        "/api/profile",
        "/api/account",
        "/api/user",
    ]

    def __init__(self, session: requests.Session, base_url: str,
                 verbose: bool = False):
        self.session  = session
        self.base_url = base_url.rstrip('/')
        self.verbose  = verbose

    def test_sensitive_data_in_responses(self) -> list[Finding]:
        """
        Test API responses for sensitive data exposure.

        Returns:
            List of Finding objects
        """
        findings = []

        for path in self.USER_DATA_ENDPOINTS:
            url = f"{self.base_url}{path}"
            try:
                response = self.session.get(url, timeout=5)

                if response.status_code not in (200, 201):
                    continue

                response_lower = response.text.lower()

                for pattern, severity, description in self.SENSITIVE_PATTERNS:
                    if pattern.lower() in response_lower:
                        findings.append(Finding(
                            test_id     = f"data-exposure-{pattern.replace('_', '-')}",
                            title       = f"Sensitive Data Exposure: {description}",
                            severity    = severity,
                            status      = TestStatus.FAIL,
                            description = (
                                f"The response from '{path}' contains the pattern "
                                f"'{pattern}', which may indicate sensitive data exposure."
                            ),
                            evidence    = (
                                f"URL: {url}\n"
                                f"Pattern found: '{pattern}'\n"
                                f"Response snippet: {response.text[:300]}"
                            ),
                            endpoint    = f"GET {url}",
                            remediation = (
                                "Apply the principle of least privilege to API responses. "
                                "Only return fields the client needs. "
                                "Use response DTOs/serializers to explicitly whitelist "
                                "fields rather than returning entire database objects. "
                                "Never return password hashes, secrets, or keys."
                            ),
                            cwe   = "CWE-200",
                            owasp = "A02:2021 - Cryptographic Failures",
                        ))

            except requests.RequestException:
                continue

        return findings

    def test_error_message_disclosure(self) -> list[Finding]:
        """
        Test whether error responses expose sensitive implementation details.
        """
        findings = []

        # Trigger various error conditions
        error_tests = [
            # (path, method, payload, description)
            ("/api/users/99999999",    "GET",  None,           "Non-existent resource"),
            ("/api/users/invalid-id",  "GET",  None,           "Invalid ID format"),
            ("/api/users",             "POST", {"invalid": 1}, "Invalid request body"),
        ]

        for path, method, payload, description in error_tests:
            url = f"{self.base_url}{path}"
            try:
                if method == "GET":
                    response = self.session.get(url, timeout=5)
                else:
                    response = self.session.post(url, json=payload, timeout=5)

                # Only check error responses
                if response.status_code < 400:
                    continue

                response_lower = response.text.lower()

                for pattern, severity, pattern_desc in self.SENSITIVE_PATTERNS:
                    if pattern.lower() in response_lower:
                        findings.append(Finding(
                            test_id     = (
                                f"error-disclosure-"
                                f"{path.replace('/', '-')}-{pattern}"
                            ),
                            title       = "Sensitive Data in Error Response",
                            severity    = severity,
                            status      = TestStatus.FAIL,
                            description = (
                                f"Error response for '{description}' contains "
                                f"'{pattern}', which may expose implementation details."
                            ),
                            evidence    = (
                                f"URL: {url}\n"
                                f"Status: {response.status_code}\n"
                                f"Pattern: '{pattern}'\n"
                                f"Response: {response.text[:300]}"
                            ),
                            endpoint    = f"{method} {url}",
                            remediation = (
                                "Return generic error messages to clients. "
                                "Log detailed errors server-side only. "
                                "Example: return {'error': 'Resource not found'} "
                                "instead of exposing stack traces or SQL errors."
                            ),
                            cwe   = "CWE-209",
                            owasp = "A05:2021 - Security Misconfiguration",
                        ))
                        break

            except requests.RequestException:
                continue

        return findings


# =============================================================================
# OpenAPI Spec Parser
# Extracts endpoints and parameters from OpenAPI/Swagger specs
# =============================================================================

class OpenAPIParser:
    """
    Parses OpenAPI 3.x and Swagger 2.x specifications to extract
    endpoints and parameters for targeted security testing.
    """

    def __init__(self, spec_path: str):
        self.spec_path = spec_path
        self.spec      = self._load_spec()

    def _load_spec(self) -> dict:
        """Load spec from file path or URL."""
        if self.spec_path.startswith("http"):
            response = requests.get(self.spec_path, timeout=10)
            response.raise_for_status()
            return response.json()
        else:
            with open(self.spec_path) as f:
                return json.load(f)

    def get_endpoints(self) -> list[dict]:
        """
        Extract all endpoints with their parameters.

        Returns:
            List of dicts with keys: path, method, parameters
        """
        endpoints = []
        paths = self.spec.get("paths", {})

        for path, path_item in paths.items():
            for method in ["get", "post", "put", "patch", "delete"]:
                operation = path_item.get(method)
                if not operation:
                    continue

                params = []

                # Extract path and query parameters
                for param in operation.get("parameters", []):
                    params.append({
                        "name":     param.get("name"),
                        "in":       param.get("in"),    # path, query, header
                        "required": param.get("required", False),
                    })

                # Extract request body fields
                request_body = operation.get("requestBody", {})
                content      = request_body.get("content", {})
                json_schema  = content.get("application/json", {})
                schema       = json_schema.get("schema", {})
                properties   = schema.get("properties", {})

                for prop_name in properties:
                    params.append({
                        "name": prop_name,
                        "in":   "body",
                        "required": prop_name in schema.get("required", []),
                    })

                endpoints.append({
                    "path":       path,
                    "method":     method.upper(),
                    "parameters": params,
                    "summary":    operation.get("summary", ""),
                })

        return endpoints


# =============================================================================
# Report Generator
# =============================================================================

class ReportGenerator:
    """
    Generates security test reports in multiple formats.
    """

    SEVERITY_ORDER = {
        Severity.CRITICAL: 0,
        Severity.HIGH:     1,
        Severity.MEDIUM:   2,
        Severity.LOW:      3,
        Severity.INFO:     4,
    }

    def __init__(self, result: TestResult):
        self.result = result

    def print_console(self, verbose: bool = False) -> None:
        """Print a formatted summary to the console."""
        summary = self.result.summary()

        print("\n" + "=" * 60)
        print(bold("  API Security Test Results"))
        print("=" * 60)
        print(f"  Target  : {self.result.target_url}")
        print(f"  Started : {self.result.scan_start}")
        print(f"  Ended   : {self.result.scan_end}")
        print(f"  Tests   : {self.result.tests_run} run, "
              f"{self.result.tests_passed} passed, "
              f"{self.result.tests_failed} failed")
        print("-" * 60)
        print("  Findings by Severity:")
        print(f"    {red('Critical')} : {summary.get('CRITICAL', 0)}")
        print(f"    {red('High')}     : {summary.get('HIGH', 0)}")
        print(f"    {yellow('Medium')}   : {summary.get('MEDIUM', 0)}")
        print(f"    {cyan('Low')}      : {summary.get('LOW', 0)}")
        print("=" * 60)

        # Sort findings by severity
        sorted_findings = sorted(
            [f for f in self.result.findings if f.status == TestStatus.FAIL],
            key=lambda f: self.SEVERITY_ORDER.get(f.severity, 99)
        )

        if not sorted_findings:
            print(green("\n  ✅ No security issues found!\n"))
            return

        print(f"\n  {bold('Findings:')}\n")

        for finding in sorted_findings:
            sev = finding.severity.value

            if sev == "CRITICAL":
                sev_display = red(f"[{sev}]")
            elif sev == "HIGH":
                sev_display = red(f"[{sev}]   ")
            elif sev == "MEDIUM":
                sev_display = yellow(f"[{sev}] ")
            else:
                sev_display = cyan(f"[{sev}]    ")

            print(f"  {sev_display} {bold(finding.title)}")
            print(f"           Endpoint : {finding.endpoint}")
            print(f"           CWE      : {finding.cwe}")
            print(f"           OWASP    : {finding.owasp}")

            if verbose:
                print(f"           Description:")
                for line in finding.description.split('\n'):
                    print(f"             {line}")
                print(f"           Evidence:")
                for line in finding.evidence.split('\n'):
                    print(f"             {line}")
                print(f"           Remediation:")
                for line in finding.remediation.split('\n'):
                    print(f"             {line}")

            print()

    def save_json(self, output_path: str) -> None:
        """
        Save results as JSON for CI/CD pipeline consumption.

        The JSON format is designed to be parsed by CI/CD tools
        to make pass/fail decisions and generate reports.
        """
        output = {
            "scan_metadata": {
                "target_url":  self.result.target_url,
                "scan_start":  self.result.scan_start,
                "scan_end":    self.result.scan_end,
                "tests_run":   self.result.tests_run,
                "tests_passed": self.result.tests_passed,
                "tests_failed": self.result.tests_failed,
                "tool":        "APISecurityTester",
                "version":     "1.0.0",
            },
            "summary": self.result.summary(),
            "findings": [
                {
                    **asdict(f),
                    "severity": f.severity.value,
                    "status":   f.status.value,
                }
                for f in sorted(
                    self.result.findings,
                    key=lambda f: self.SEVERITY_ORDER.get(f.severity, 99)
                )
            ],
        }

        with open(output_path, "w") as f:
            json.dump(output, f, indent=2)

        print(f"\n  📄 JSON report saved to: {output_path}")

    def save_html(self, output_path: str) -> None:
        """Save results as a self-contained HTML report."""

        summary  = self.result.summary()
        findings = sorted(
            self.result.findings,
            key=lambda f: self.SEVERITY_ORDER.get(f.severity, 99)
        )

        # Build findings HTML
        findings_html = ""
        for f in findings:
            sev = f.severity.value
            color_map = {
                "CRITICAL": "#dc3545",
                "HIGH":     "#fd7e14",
                "MEDIUM":   "#ffc107",
                "LOW":      "#17a2b8",
                "INFO":     "#6c757d",
            }
            color = color_map.get(sev, "#6c757d")

            status_icon = "❌" if f.status == TestStatus.FAIL else "✅"

            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color};">
                <div class="finding-header">
                    <span class="badge" style="background:{color};">{sev}</span>
                    <strong>{status_icon} {f.title}</strong>
                </div>
                <table class="finding-details">
                    <tr><td>Endpoint</td><td><code>{f.endpoint}</code></td></tr>
                    <tr><td>CWE</td><td>{f.cwe}</td></tr>
                    <tr><td>OWASP</td><td>{f.owasp}</td></tr>
                    <tr><td>Description</td><td>{f.description}</td></tr>
                    <tr><td>Evidence</td><td><pre>{f.evidence}</pre></td></tr>
                    <tr><td>Remediation</td><td>{f.remediation}</td></tr>
                </table>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Security Test Report</title>
    <style>
        body        {{ font-family: -apple-system, BlinkMacSystemFont,
                       'Segoe UI', sans-serif; margin: 0; padding: 20px;
                       background: #f8f9fa; color: #212529; }}
        .container  {{ max-width: 1100px; margin: 0 auto; }}
        h1          {{ color: #343a40; border-bottom: 2px solid #dee2e6;
                       padding-bottom: 10px; }}
        .meta       {{ background: #fff; padding: 15px; border-radius: 6px;
                       margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
        .summary    {{ display: flex; gap: 15px; margin-bottom: 20px;
                       flex-wrap: wrap; }}
        .stat-card  {{ background: #fff; padding: 15px 25px; border-radius: 6px;
                       text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,.1);
                       min-width: 100px; }}
        .stat-card .count {{ font-size: 2em; font-weight: bold; }}
        .finding    {{ background: #fff; padding: 15px; border-radius: 6px;
                       margin-bottom: 15px;
                       box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
        .finding-header {{ margin-bottom: 10px; font-size: 1.05em; }}
        .badge      {{ color: #fff; padding: 2px 8px; border-radius: 4px;
                       font-size: 0.8em; margin-right: 8px; }}
        .finding-details {{ width: 100%; border-collapse: collapse;
                            font-size: 0.9em; }}
        .finding-details td {{ padding: 5px 10px; vertical-align: top;
                               border-bottom: 1px solid #f0f0f0; }}
        .finding-details td:first-child {{ font-weight: bold; width: 120px;
                                           color: #6c757d; }}
        pre         {{ background: #f8f9fa; padding: 8px; border-radius: 4px;
                       white-space: pre-wrap; word-break: break-all;
                       margin: 0; font-size: 0.85em; }}
        code        {{ background: #f8f9fa; padding: 2px 5px;
                       border-radius: 3px; }}
    </style>
</head>
<body>
<div class="container">
    <h1>🔒 API Security Test Report</h1>

    <div class="meta">
        <strong>Target:</strong> {self.result.target_url}<br>
        <strong>Scan Start:</strong> {self.result.scan_start}<br>
        <strong>Scan End:</strong>   {self.result.scan_end}<br>
        <strong>Tests Run:</strong>  {self.result.tests_run}
        ({self.result.tests_passed} passed,
         {self.result.tests_failed} failed)
    </div>

    <div class="summary">
        <div class="stat-card">
            <div class="count" style="color:#dc3545;">
                {summary.get("CRITICAL", 0)}
            </div>
            <div>Critical</div>
        </div>
        <div class="stat-card">
            <div class="count" style="color:#fd7e14;">
                {summary.get("HIGH", 0)}
            </div>
            <div>High</div>
        </div>
        <div class="stat-card">
            <div class="count" style="color:#ffc107;">
                {summary.get("MEDIUM", 0)}
            </div>
            <div>Medium</div>
        </div>
        <div class="stat-card">
            <div class="count" style="color:#17a2b8;">
                {summary.get("LOW", 0)}
            </div>
            <div>Low</div>
        </div>
    </div>

    <h2>Findings</h2>
    {findings_html if findings_html else
     '<p style="color:green;">✅ No security issues found.</p>'}

</div>
</body>
</html>"""

        with open(output_path, "w") as f:
            f.write(html)

        print(f"  🌐 HTML report saved to: {output_path}")


# =============================================================================
# Main Scanner Orchestrator
# =============================================================================

class APISecurityScanner:
    """
    Orchestrates all security tests and aggregates results.

    Principle: Provide Context - runs all tests and produces a single
    unified report with actionable remediation guidance.
    """

    def __init__(self, base_url: str, token: Optional[str] = None,
                 spec_path: Optional[str] = None, verbose: bool = False):
        self.base_url  = base_url.rstrip('/')
        self.token     = token
        self.spec_path = spec_path
        self.verbose   = verbose
        self.session   = build_session(token=token, verify_ssl=False)

        self.result = TestResult(
            target_url = base_url,
            scan_start = datetime.now(timezone.utc).isoformat(),
        )

    def _log(self, message: str) -> None:
        if self.verbose:
            print(f"  {message}")

    def _run_test_suite(self, suite_name: str,
                        findings: list[Finding]) -> None:
        """Record results from a test suite."""
        self.result.tests_run += 1
        failed = [f for f in findings if f.status == TestStatus.FAIL]

        if failed:
            self.result.tests_failed += 1
            print(f"  {red('FAIL')} {suite_name} "
                  f"({len(failed)} finding(s))")
        else:
            self.result.tests_passed += 1
            print(f"  {green('PASS')} {suite_name}")

        self.result.findings.extend(findings)

    def run(self) -> TestResult:
        """
        Execute all security test suites.

        Returns:
            TestResult with all findings
        """
        print(f"\n{bold('🔍 API Security Scanner')}")
        print(f"   Target : {self.base_url}")
        print(f"   Auth   : {'Yes (Bearer token)' if self.token else 'No'}")
        print(f"   Spec   : {self.spec_path or 'None (using default endpoints)'}")
        print(f"   Time   : {self.result.scan_start}")
        print("-" * 60)
        print(f"\n{bold('Running security tests...')}\n")

        # -----------------------------------------------------------------------
        # Determine endpoints to test
        # Use OpenAPI spec if provided, otherwise use common defaults
        # -----------------------------------------------------------------------
        if self.spec_path:
            self._log(f"Loading OpenAPI spec from {self.spec_path}")
            try:
                parser    = OpenAPIParser(self.spec_path)
                endpoints = parser.get_endpoints()
                self._log(f"Found {len(endpoints)} endpoints in spec")
            except Exception as e:
                print(f"  ⚠️  Could not load spec: {e}. Using defaults.")
                endpoints = self._default_endpoints()
        else:
            endpoints = self._default_endpoints()

        # -----------------------------------------------------------------------
        # Test Suite 1: Security Headers
        # Fast, no auth required, high signal-to-noise ratio
        # -----------------------------------------------------------------------
        print(f"{bold('[ Security Headers ]')}")
        headers_tester = SecurityHeadersTester(
            self.session, self.base_url, self.verbose
        )
        self._run_test_suite(
            "Security headers check",
            headers_tester.test_security_headers()
        )

        # -----------------------------------------------------------------------
        # Test Suite 2: Authentication Bypass
        # -----------------------------------------------------------------------
        print(f"\n{bold('[ Authentication & Authorization ]')}")
        auth_tester = AuthBypassTester(
            self.session, self.base_url, self.token, self.verbose
        )

        self._run_test_suite(
            "Unauthenticated access to sensitive endpoints",
            auth_tester.test_unauthenticated_access()
        )
        self._run_test_suite(
            "JWT none algorithm vulnerability",
            auth_tester.test_jwt_none_algorithm()
        )
        self._run_test_suite(
            "Horizontal privilege escalation (IDOR)",
            auth_tester.test_horizontal_privilege_escalation()
        )

        # -----------------------------------------------------------------------
        # Test Suite 3: Injection Testing
        # Test each endpoint's parameters
        # -----------------------------------------------------------------------
        print(f"\n{bold('[ Injection Testing ]')}")
        sqli_tester = SQLInjectionTester(
            self.session, self.base_url, self.verbose
        )
        xss_tester = XSSTester(
            self.session, self.base_url, self.verbose
        )

        for endpoint in endpoints:
            path   = endpoint["path"]
            method = endpoint["method"]

            for param in endpoint.get("parameters", []):
                param_name = param.get("name")
                if not param_name:
                    continue

                # Only test query and body params - not headers
                if param.get("in") not in ("query", "body", "formData"):
                    continue

                self._run_test_suite(
                    f"SQL injection: {method} {path} [{param_name}]",
                    sqli_tester.test_endpoint(path, param_name, method)
                )
                self._run_test_suite(
                    f"XSS: {method} {path} [{param_name}]",
                    xss_tester.test_endpoint(path, param_name, method)
                )

        # -----------------------------------------------------------------------
        # Test Suite 4: Rate Limiting
        # -----------------------------------------------------------------------
        print(f"\n{bold('[ Rate Limiting ]')}")
        rate_tester = RateLimitTester(
            self.session, self.base_url, self.verbose
        )
        self._run_test_suite(
            "Rate limiting on authentication endpoints",
            rate_tester.test_rate_limiting()
        )

        # -----------------------------------------------------------------------
        # Test Suite 5: Sensitive Data Exposure
        # -----------------------------------------------------------------------
        print(f"\n{bold('[ Sensitive Data Exposure ]')}")
        data_tester = SensitiveDataExposureTester(
            self.session, self.base_url, self.verbose
        )
        self._run_test_suite(
            "Sensitive data in API responses",
            data_tester.test_sensitive_data_in_responses()
        )
        self._run_test_suite(
            "Sensitive data in error responses",
            data_tester.test_error_message_disclosure()
        )

        # -----------------------------------------------------------------------
        # Finalize results
        # -----------------------------------------------------------------------
        self.result.scan_end = datetime.now(timezone.utc).isoformat()
        return self.result

    def _default_endpoints(self) -> list[dict]:
        """
        Default endpoints to test when no OpenAPI spec is provided.
        Covers common REST API patterns.
        """
        return [
            {
                "path":   "/api/users",
                "method": "GET",
                "parameters": [
                    {"name": "search", "in": "query"},
                    {"name": "filter", "in": "query"},
                    {"name": "id",     "in": "query"},
                ],
            },
            {
                "path":   "/api/users",
                "method": "POST",
                "parameters": [
                    {"name": "username", "in": "body"},
                    {"name": "email",    "in": "body"},
                    {"name": "name",     "in": "body"},
                ],
            },
            {
                "path":   "/api/products",
                "method": "GET",
                "parameters": [
                    {"name": "search",   "in": "query"},
                    {"name": "category", "in": "query"},
                    {"name": "id",       "in": "query"},
                ],
            },
            {
                "path":   "/api/search",
                "method": "GET",
                "parameters": [
                    {"name": "q",     "in": "query"},
                    {"name": "query", "in": "query"},
                ],
            },
        ]


# =============================================================================
# CI/CD Exit Code Helper
# =============================================================================

def get_exit_code(result: TestResult,
                  fail_on: list[str] = None) -> int:
    """
    Determine the appropriate exit code for CI/CD pipelines.

    Args:
        result:  The completed TestResult
        fail_on: List of severity levels that should cause non-zero exit
                 Default: ["CRITICAL", "HIGH"]

    Returns:
        0 = pass, 1 = findings at or above threshold, 2 = scan error
    """
    if fail_on is None:
        fail_on = ["CRITICAL", "HIGH"]

    summary = result.summary()

    for severity in fail_on:
        if summary.get(severity, 0) > 0:
            return 1

    return 0


# =============================================================================
# CLI Entry Point
# =============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="API Security Tester - Chapter 3, Section 3.1.3.2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan (no auth)
  python api-security-tester.py --url https://staging.yourapp.com/api

  # Authenticated scan
  python api-security-tester.py \\
    --url https://staging.yourapp.com/api \\
    --token eyJhbGciOiJIUzI1NiJ9...

  # Scan from OpenAPI spec with JSON output
  python api-security-tester.py \\
    --url https://staging.yourapp.com/api \\
    --spec openapi.json \\
    --output results.json \\
    --html-output results.html

  # Fail only on critical findings (for CI/CD)
  python api-security-tester.py \\
    --url https://staging.yourapp.com/api \\
    --fail-on CRITICAL

  # Verbose output with full finding details
  python api-security-tester.py \\
    --url https://staging.yourapp.com/api \\
    --verbose
        """,
    )

    parser.add_argument(
        "--url",
        required=True,
        help="Base URL of the API to test (e.g., https://staging.yourapp.com/api)",
    )
    parser.add_argument(
        "--token",
        default=None,
        help="Bearer token for authenticated requests",
    )
    parser.add_argument(
        "--spec",
        default=None,
        help="Path or URL to OpenAPI/Swagger spec (JSON format)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Path to save JSON results (e.g., results.json)",
    )
    parser.add_argument(
        "--html-output",
        default=None,
        help="Path to save HTML report (e.g., results.html)",
    )
    parser.add_argument(
        "--fail-on",
        default="HIGH",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Minimum severity level that causes a non-zero exit code (default: HIGH)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print full finding details including evidence and remediation",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Map fail-on severity to list of severities at or above threshold
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    threshold_idx  = severity_order.index(args.fail_on)
    fail_on        = severity_order[:threshold_idx + 1]

    # Run the scanner
    scanner = APISecurityScanner(
        base_url   = args.url,
        token      = args.token,
        spec_path  = args.spec,
        verbose    = args.verbose,
    )

    result = scanner.run()

    # Generate reports
    reporter = ReportGenerator(result)
    reporter.print_console(verbose=args.verbose)

    if args.output:
        reporter.save_json(args.output)

    if args.html_output:
        reporter.save_html(args.html_output)

    # Exit with appropriate code for CI/CD
    # Principle: Fail Fast - non-zero exit blocks the pipeline
    exit_code = get_exit_code(result, fail_on=fail_on)

    if exit_code != 0:
        summary = result.summary()
        print(
            red(f"\n❌ Security scan FAILED. "
                f"Findings at or above '{args.fail_on}' threshold detected.")
        )
        print(f"   Critical : {summary.get('CRITICAL', 0)}")
        print(f"   High     : {summary.get('HIGH', 0)}")
        print(f"\n   Fix the above issues and re-run the scan.\n")
    else:
        print(green(f"\n✅ Security scan PASSED. "
                    f"No findings at or above '{args.fail_on}' threshold.\n"))

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
