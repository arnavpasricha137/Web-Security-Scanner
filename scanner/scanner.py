"""
Scan orchestrator — ties together header auditing, CORS probing,
and TLS/redirect checks into a single ScanResult.
"""

from __future__ import annotations
import time
import socket
import ssl
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from scanner.headers import audit_headers, score_headers, HeaderFinding, LeakyHeaderFinding
from scanner.cors import probe_cors, cors_score, CORSFinding


# ---------------------------------------------------------------------------
# TLS info model
# ---------------------------------------------------------------------------

@dataclass
class TLSInfo:
    enabled: bool
    version: Optional[str] = None
    cipher: Optional[str] = None
    cert_subject: Optional[str] = None
    cert_expiry: Optional[str] = None
    days_until_expiry: Optional[int] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Redirect info model
# ---------------------------------------------------------------------------

@dataclass
class RedirectInfo:
    http_redirects_to_https: bool
    redirect_chain: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Full scan result
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    url: str
    scanned_at: str
    elapsed_seconds: float
    status_code: Optional[int]
    final_url: Optional[str]
    tls: TLSInfo
    redirect: RedirectInfo
    header_findings: list[HeaderFinding]
    leaky_headers: list[LeakyHeaderFinding]
    cors_findings: list[CORSFinding]
    header_score: int
    cors_score_val: int
    overall_score: int
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# TLS helper
# ---------------------------------------------------------------------------

def _get_tls_info(hostname: str, port: int = 443) -> TLSInfo:
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, port), timeout=5), server_hostname=hostname) as s:
            cert = s.getpeercert()
            ver = s.version()
            cipher_info = s.cipher()
            subject = dict(x[0] for x in cert.get("subject", []))
            expiry_str = cert.get("notAfter", "")
            expiry_dt = None
            days = None
            if expiry_str:
                expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days = (expiry_dt - datetime.now(timezone.utc)).days

            return TLSInfo(
                enabled=True,
                version=ver,
                cipher=cipher_info[0] if cipher_info else None,
                cert_subject=subject.get("commonName"),
                cert_expiry=expiry_dt.strftime("%Y-%m-%d") if expiry_dt else None,
                days_until_expiry=days,
            )
    except Exception as e:
        return TLSInfo(enabled=False, error=str(e))


# ---------------------------------------------------------------------------
# Redirect helper
# ---------------------------------------------------------------------------

def _check_redirect(url: str, timeout: int) -> RedirectInfo:
    parsed = urlparse(url)
    http_url = f"http://{parsed.netloc}{parsed.path}"
    try:
        resp = requests.get(http_url, timeout=timeout, allow_redirects=True, verify=False)
        chain = [r.url for r in resp.history] + [resp.url]
        redirects_https = resp.url.startswith("https://")
        return RedirectInfo(http_redirects_to_https=redirects_https, redirect_chain=chain)
    except Exception:
        return RedirectInfo(http_redirects_to_https=False, redirect_chain=[])


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

def scan(url: str, timeout: int = 10, scan_cors: bool = True) -> ScanResult:
    """
    Perform a full security scan of *url*.
    Returns a ScanResult with header, CORS, TLS, and redirect findings.
    """
    start = time.time()
    scanned_at = datetime.now(timezone.utc).isoformat()

    # Ensure scheme
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # --- Fetch main response ---
    status_code = None
    final_url = None
    response_headers: dict[str, str] = {}
    fetch_error = None

    try:
        session = requests.Session()
        resp = session.get(url, timeout=timeout, allow_redirects=True, verify=True)
        status_code = resp.status_code
        final_url = resp.url
        response_headers = dict(resp.headers)
    except requests.exceptions.SSLError:
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True, verify=False)
            status_code = resp.status_code
            final_url = resp.url
            response_headers = dict(resp.headers)
        except Exception as e:
            fetch_error = str(e)
    except Exception as e:
        fetch_error = str(e)

    # --- Headers audit ---
    header_findings, leaky = audit_headers(response_headers)
    h_score = score_headers(header_findings)

    # --- CORS probes ---
    target_url = final_url or url
    cors_findings: list[CORSFinding] = []
    if scan_cors and not fetch_error:
        cors_findings = probe_cors(target_url, timeout=timeout)

    c_score = cors_score(cors_findings)

    # --- TLS info ---
    tls = _get_tls_info(hostname, port=parsed.port or 443)

    # --- Redirect check ---
    redirect = _check_redirect(url, timeout)

    # --- Overall score ---
    overall = int(h_score * 0.55 + c_score * 0.45)

    elapsed = round(time.time() - start, 2)

    return ScanResult(
        url=url,
        scanned_at=scanned_at,
        elapsed_seconds=elapsed,
        status_code=status_code,
        final_url=final_url,
        tls=tls,
        redirect=redirect,
        header_findings=header_findings,
        leaky_headers=leaky,
        cors_findings=cors_findings,
        header_score=h_score,
        cors_score_val=c_score,
        overall_score=overall,
        error=fetch_error,
    )
