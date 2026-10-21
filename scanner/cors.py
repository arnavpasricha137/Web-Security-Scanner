"""
CORS (Cross-Origin Resource Sharing) Flaw Auditor
Sends a series of preflight and simple cross-origin probes to detect
misconfigurations.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import requests


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------

@dataclass
class CORSFinding:
    test_name: str
    origin_sent: str
    severity: str           # HIGH / MEDIUM / LOW / INFO
    status: str             # PASS / FAIL / INFO
    acao_header: Optional[str]
    acac_header: Optional[str]  # Access-Control-Allow-Credentials
    details: str
    recommendation: str


# ---------------------------------------------------------------------------
# Test payloads
# ---------------------------------------------------------------------------

_PROBES: list[dict] = [
    {
        "name": "Wildcard Origin (*)",
        "origin": "https://evil.com",
        "expect_fail_if": lambda acao, acac: acao == "*",
        "severity": "MEDIUM",
        "details": "Server returns ACAO: * — any origin can read the response. "
                   "Not exploitable with credentials, but exposes public APIs.",
        "recommendation": "Replace wildcard with an explicit allowlist of trusted origins.",
    },
    {
        "name": "Wildcard + Credentials",
        "origin": "https://evil.com",
        "preflight": True,
        "expect_fail_if": lambda acao, acac: (
            acao == "*" and acac is not None and acac.lower() == "true"
        ),
        "severity": "HIGH",
        "details": "ACAO: * combined with ACAC: true is an invalid but dangerous combination "
                   "that some browsers may honour, allowing any origin to send cookies.",
        "recommendation": "Never combine wildcard ACAO with ACAC: true.",
    },
    {
        "name": "Arbitrary Origin Reflection",
        "origin": "https://evil.com",
        "expect_fail_if": lambda acao, acac: acao == "https://evil.com",
        "severity": "HIGH",
        "details": "Server reflects the supplied Origin header verbatim. "
                   "An attacker-controlled page can read cross-origin responses.",
        "recommendation": "Validate the Origin against a strict server-side allowlist.",
    },
    {
        "name": "Credentialed Arbitrary Origin",
        "origin": "https://evil.com",
        "preflight": True,
        "expect_fail_if": lambda acao, acac: (
            acao == "https://evil.com"
            and acac is not None
            and acac.lower() == "true"
        ),
        "severity": "CRITICAL",
        "details": "Server reflects arbitrary origins AND allows credentials. "
                   "This is a critical CORS misconfiguration — attackers can perform "
                   "authenticated cross-origin requests and steal sensitive data.",
        "recommendation": "Validate origins server-side. Never echo Origin with ACAC: true.",
    },
    {
        "name": "Null Origin Allowed",
        "origin": "null",
        "expect_fail_if": lambda acao, acac: acao == "null",
        "severity": "HIGH",
        "details": "Server trusts 'null' Origin, which is produced by sandboxed iframes, "
                   "local file:// pages, and data: URIs — easy for attackers to forge.",
        "recommendation": "Remove 'null' from the CORS origin allowlist.",
    },
    {
        "name": "Subdomain Wildcard via Prefix Bypass",
        "origin": "https://evil.com",
        "expect_fail_if": lambda acao, acac: acao == "https://evil.com",
        "severity": "MEDIUM",
        "details": "Covered by the arbitrary reflection test. A regex like .*\\.example\\.com "
                   "that can be fooled by evilexample.com or notexample.com.",
        "recommendation": "Anchor subdomain regex: ^https://[a-z0-9-]+\\.example\\.com$",
    },
    {
        "name": "HTTP (non-TLS) Origin Accepted",
        "origin": "http://evil.com",
        "expect_fail_if": lambda acao, acac: acao == "http://evil.com",
        "severity": "MEDIUM",
        "details": "Server allows a plain-HTTP origin. Responses can be intercepted "
                   "via MitM when the requesting page is over HTTP.",
        "recommendation": "Only trust HTTPS origins; reject http:// scheme origins.",
    },
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def probe_cors(
    url: str,
    timeout: int = 10,
    session: Optional[requests.Session] = None,
) -> list[CORSFinding]:
    """
    Send CORS probes to *url* and return a list of CORSFinding objects.
    """
    s = session or requests.Session()
    s.verify = True
    findings: list[CORSFinding] = []

    for probe in _PROBES:
        origin = probe["origin"]
        is_preflight = probe.get("preflight", False)

        try:
            if is_preflight:
                resp = s.options(
                    url,
                    headers={
                        "Origin": origin,
                        "Access-Control-Request-Method": "GET",
                        "Access-Control-Request-Headers": "Authorization",
                    },
                    timeout=timeout,
                    allow_redirects=True,
                )
            else:
                resp = s.get(
                    url,
                    headers={"Origin": origin},
                    timeout=timeout,
                    allow_redirects=True,
                )
        except requests.exceptions.SSLError:
            # Retry without verification to still gather CORS headers
            try:
                s.verify = False
                resp = s.get(url, headers={"Origin": origin}, timeout=timeout)
            except Exception as exc:
                findings.append(
                    CORSFinding(
                        test_name=probe["name"],
                        origin_sent=origin,
                        severity=probe["severity"],
                        status="INFO",
                        acao_header=None,
                        acac_header=None,
                        details=f"Request failed: {exc}",
                        recommendation=probe["recommendation"],
                    )
                )
                continue
        except Exception as exc:
            findings.append(
                CORSFinding(
                    test_name=probe["name"],
                    origin_sent=origin,
                    severity=probe["severity"],
                    status="INFO",
                    acao_header=None,
                    acac_header=None,
                    details=f"Request failed: {exc}",
                    recommendation=probe["recommendation"],
                )
            )
            continue

        acao = resp.headers.get("Access-Control-Allow-Origin")
        acac = resp.headers.get("Access-Control-Allow-Credentials")

        failed = probe["expect_fail_if"](acao, acac)
        status = "FAIL" if failed else "PASS"
        sev = probe["severity"] if failed else "INFO"

        findings.append(
            CORSFinding(
                test_name=probe["name"],
                origin_sent=origin,
                severity=sev,
                status=status,
                acao_header=acao,
                acac_header=acac,
                details=probe["details"] if failed else "No issue detected for this probe.",
                recommendation=probe["recommendation"] if failed else "—",
            )
        )

    return findings


def cors_score(findings: list[CORSFinding]) -> int:
    """Return a 0–100 score; deduct points for each failed CORS probe."""
    weight = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 15, "LOW": 5}
    deducted = sum(weight.get(f.severity, 0) for f in findings if f.status == "FAIL")
    return max(0, 100 - deducted)
