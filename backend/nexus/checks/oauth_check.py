"""
OAuth 2.0 vulnerability check — uses oauth_engine.py.

OAuthCheck:
  1. Missing state parameter (CSRF on OAuth flow)
  2. Open redirect in redirect_uri (token theft)
  3. Token leakage via URL / Referrer

Anti-hallucination:
  - Missing state: server must return 200/302 (accepts request, not 400)
  - Redirect bypass: server must redirect to attacker URL
  - Token leakage: token must actually appear in crawled URLs
"""
from urllib.parse import urlparse

import httpx

from nexus.models import (
    CheckResult,
    CheckType,
    Confidence,
    CrawlResult,
    InsertionPoint,
    Severity,
)
from nexus.tools.oauth_engine import audit_oauth, OAuthResult
from .base import BaseScanCheck


_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH":     Severity.HIGH,
    "MEDIUM":   Severity.MEDIUM,
    "LOW":      Severity.LOW,
    "INFO":     Severity.INFO,
}

_CVSS_MAP = {
    "CRITICAL": 9.1,
    "HIGH":     7.5,
    "MEDIUM":   5.4,
    "LOW":      3.1,
    "INFO":     0.0,
}


class OAuthCheck(BaseScanCheck):
    """
    Comprehensive OAuth 2.0 attack suite:
    - Missing state parameter → CSRF on authorization flow
    - redirect_uri bypass → token theft via open redirect
    - Token leakage in URL / Referrer header
    """
    check_id = "oauth"
    check_type = CheckType.ACTIVE
    name = "OAuth 2.0 Vulnerabilities"
    description = "Tests OAuth endpoints for CSRF (missing state), redirect_uri bypass, token leakage"

    _attempted: bool = False

    # Store crawl results from passive phase for passive token check
    _crawl_results: list[CrawlResult] = []

    async def check_passive(self, crawl_result: CrawlResult) -> list[CheckResult]:
        """Collect crawl results for later passive token-in-URL analysis."""
        self.__class__._crawl_results.append(crawl_result)
        return []

    async def check_active(
        self,
        insertion_point: InsertionPoint,
        client: httpx.AsyncClient,
    ) -> list[CheckResult]:
        # Only run once per scan
        if getattr(self.__class__, "_attempted", False):
            return []
        self.__class__._attempted = True

        parsed = urlparse(insertion_point.url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        crawl = getattr(self.__class__, "_crawl_results", [])
        oauth_results = await audit_oauth(client, base, crawl_results=crawl)

        findings: list[CheckResult] = []
        for ar in oauth_results:
            if not ar.confirmed:
                continue
            # Skip INFO-only endpoint-found unless there's actual attack confirmed
            if ar.attack_type == "oauth-endpoint-found" and ar.severity == "INFO":
                continue

            sev_str = ar.severity.upper()
            sev = _SEVERITY_MAP.get(sev_str, Severity.MEDIUM)
            cvss = _CVSS_MAP.get(sev_str, 5.4)

            # Confidence based on attack type
            if ar.attack_type in ("oauth-open-redirect", "oauth-token-referrer", "oauth-token-in-page"):
                conf = Confidence.CERTAIN
            elif ar.attack_type == "oauth-missing-state":
                conf = Confidence.FIRM  # Server accepted, but user interaction needed to confirm full CSRF
            else:
                conf = Confidence.TENTATIVE

            findings.append(CheckResult(
                check_id=self.check_id,
                vulnerable=True,
                confidence=conf,
                severity=sev,
                cvss=cvss,
                description=f"OAuth vulnerability [{ar.attack_type}]: {ar.evidence}",
                evidence=self._make_evidence(
                    request_raw=f"GET {ar.endpoint} HTTP/1.1\nHost: {parsed.netloc}",
                    response=None,
                    payload=ar.endpoint,
                    poc_curl=ar.poc_steps,
                ),
                insertion_point=insertion_point,
            ))

        return findings

    def reset(self):
        super().reset()
        self.__class__._attempted = False
        self.__class__._crawl_results = []
