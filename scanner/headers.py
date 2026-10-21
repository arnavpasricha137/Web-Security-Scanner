"""
Security Headers Auditor
Checks for the presence and correctness of HTTP security response headers.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import re


# ---------------------------------------------------------------------------
# Header definitions
# ---------------------------------------------------------------------------

SECURITY_HEADERS: dict[str, dict] = {
    "Strict-Transport-Security": {
        "description": "Forces HTTPS for a specified duration.",
        "severity": "HIGH",
        "recommendation": (
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        ),
        "validators": ["_validate_hsts"],
    },
    "Content-Security-Policy": {
        "description": "Restricts sources of content to mitigate XSS.",
        "severity": "HIGH",
        "recommendation": (
            "Define a strict CSP, e.g.: Content-Security-Policy: default-src 'self'"
        ),
        "validators": ["_validate_csp"],
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking by controlling framing.",
        "severity": "MEDIUM",
        "recommendation": "Add: X-Frame-Options: DENY  (or SAMEORIGIN)",
        "validators": ["_validate_xfo"],
    },
    "X-Content-Type-Options": {
        "description": "Stops browsers from MIME-sniffing a response.",
        "severity": "MEDIUM",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
        "validators": ["_validate_xcto"],
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information is sent.",
        "severity": "LOW",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "validators": ["_validate_referrer_policy"],
    },
    "Permissions-Policy": {
        "description": "Restricts access to browser features (camera, microphone, etc.).",
        "severity": "LOW",
        "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        "validators": [],
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter — deprecated but still checked.",
        "severity": "LOW",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block  (or remove if CSP is strong)",
        "validators": ["_validate_xxss"],
    },
    "Cache-Control": {
        "description": "Prevents sensitive data from being cached.",
        "severity": "LOW",
        "recommendation": "Add: Cache-Control: no-store, no-cache, must-revalidate",
        "validators": [],
    },
}

# Informational-only headers (not security critical, but noteworthy)
LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------

@dataclass
class HeaderFinding:
    header: str
    present: bool
    value: Optional[str]
    severity: str          # HIGH / MEDIUM / LOW / INFO
    status: str            # PASS / WARN / FAIL
    description: str
    recommendation: str
    notes: list[str] = field(default_factory=list)


@dataclass
class LeakyHeaderFinding:
    header: str
    value: str
    note: str


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

def _validate_hsts(value: str) -> list[str]:
    notes = []
    if "max-age" not in value.lower():
        notes.append("Missing max-age directive.")
    else:
        m = re.search(r"max-age=(\d+)", value, re.IGNORECASE)
        if m and int(m.group(1)) < 31536000:
            notes.append(f"max-age={m.group(1)} is less than the recommended 31536000 (1 year).")
    if "includesubdomains" not in value.lower():
        notes.append("includeSubDomains is missing.")
    if "preload" not in value.lower():
        notes.append("preload directive is missing (required for HSTS preload list).")
    return notes


def _validate_csp(value: str) -> list[str]:
    notes = []
    dangerous = ["unsafe-inline", "unsafe-eval", "unsafe-hashes"]
    for d in dangerous:
        if d in value.lower():
            notes.append(f"CSP contains '{d}' which weakens the policy.")
    if "default-src" not in value.lower() and "script-src" not in value.lower():
        notes.append("CSP lacks a default-src or script-src directive.")
    if "*" in value:
        notes.append("Wildcard (*) source detected — overly permissive.")
    return notes


def _validate_xfo(value: str) -> list[str]:
    notes = []
    upper = value.strip().upper()
    valid = {"DENY", "SAMEORIGIN"}
    if upper not in valid and not upper.startswith("ALLOW-FROM"):
        notes.append(f"Unrecognised X-Frame-Options value: '{value}'.")
    if upper.startswith("ALLOW-FROM"):
        notes.append("ALLOW-FROM is deprecated and ignored in most modern browsers.")
    return notes


def _validate_xcto(value: str) -> list[str]:
    if value.strip().lower() != "nosniff":
        return [f"Expected 'nosniff', got '{value}'."]
    return []


def _validate_referrer_policy(value: str) -> list[str]:
    safe_values = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    }
    if value.strip().lower() not in safe_values:
        return [f"Value '{value}' is not a recognised Referrer-Policy token."]
    weak = {"unsafe-url", "no-referrer-when-downgrade"}
    if value.strip().lower() in weak:
        return [f"'{value}' can leak full URLs to third-party sites — consider tightening."]
    return []


def _validate_xxss(value: str) -> list[str]:
    notes = []
    if value.strip() == "0":
        notes.append("X-XSS-Protection is disabled (0).")
    elif "mode=block" not in value.lower():
        notes.append("Add 'mode=block' to actively block detected attacks.")
    return notes


_VALIDATOR_MAP = {
    "_validate_hsts": _validate_hsts,
    "_validate_csp": _validate_csp,
    "_validate_xfo": _validate_xfo,
    "_validate_xcto": _validate_xcto,
    "_validate_referrer_policy": _validate_referrer_policy,
    "_validate_xxss": _validate_xxss,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def audit_headers(response_headers: dict[str, str]) -> tuple[list[HeaderFinding], list[LeakyHeaderFinding]]:
    """
    Analyse response headers and return (security_findings, leaky_findings).
    response_headers should be a case-insensitive dict (e.g. requests.Response.headers).
    """
    # Normalise to lower-case lookup
    normalised = {k.lower(): v for k, v in response_headers.items()}

    findings: list[HeaderFinding] = []
    for header, meta in SECURITY_HEADERS.items():
        value = normalised.get(header.lower())
        present = value is not None

        notes: list[str] = []
        if present:
            for fn_name in meta["validators"]:
                fn = _VALIDATOR_MAP.get(fn_name)
                if fn:
                    notes.extend(fn(value))
            status = "WARN" if notes else "PASS"
        else:
            status = "FAIL"

        findings.append(
            HeaderFinding(
                header=header,
                present=present,
                value=value,
                severity=meta["severity"],
                status=status,
                description=meta["description"],
                recommendation=meta["recommendation"],
                notes=notes,
            )
        )

    leaky: list[LeakyHeaderFinding] = []
    for lh in LEAKY_HEADERS:
        val = normalised.get(lh.lower())
        if val:
            leaky.append(
                LeakyHeaderFinding(
                    header=lh,
                    value=val,
                    note=f"Exposes server technology. Consider suppressing '{lh}'.",
                )
            )

    return findings, leaky


def score_headers(findings: list[HeaderFinding]) -> int:
    """Return a 0-100 security score based on header findings."""
    weights = {"HIGH": 30, "MEDIUM": 20, "LOW": 10}
    total_weight = sum(weights[m["severity"]] for m in SECURITY_HEADERS.values())
    deducted = 0
    for f in findings:
        w = weights[f.severity]
        if f.status == "FAIL":
            deducted += w
        elif f.status == "WARN":
            deducted += w // 2
    score = max(0, 100 - int((deducted / total_weight) * 100))
    return score
