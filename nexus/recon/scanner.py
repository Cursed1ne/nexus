"""
LLMScanner - Discovers and enumerates LLM-powered endpoints.
Inspired by Aztarna's robot endpoint discovery capabilities.

Scans for:
  - OpenAI-compatible /v1/chat/completions endpoints
  - Ollama instances
  - HuggingFace Inference API endpoints
  - LLM proxies (LiteLLM, OpenRouter, etc.)
  - Custom API gateways
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredEndpoint:
    url: str
    endpoint_type: str = "unknown"
    authenticated: bool = False
    models_available: List[str] = field(default_factory=list)
    response_headers: Dict[str, str] = field(default_factory=dict)
    fingerprint: str = ""


class LLMScanner:
    """
    Discovers LLM API endpoints on a host or network range.

    Like Aztarna scans for ROS/ROS2 instances, LLMScanner
    probes common ports and paths for LLM serving infrastructure.
    """

    COMMON_PORTS = [80, 443, 1234, 3000, 5000, 7860, 8000, 8080, 8443, 11434]

    ENDPOINT_PROBES = [
        ("/v1/models", "openai_compat"),
        ("/api/tags", "ollama"),
        ("/api/models", "generic"),
        ("/v1/chat/completions", "openai_compat"),
        ("/generate", "huggingface"),
        ("/chat", "generic"),
        ("/completions", "openai_compat"),
    ]

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self._discovered: List[DiscoveredEndpoint] = []

    def scan_host(self, host: str, ports: Optional[List[int]] = None) -> List[DiscoveredEndpoint]:
        """Scan a single host for LLM API endpoints."""
        ports = ports or self.COMMON_PORTS
        found = []

        for port in ports:
            for scheme in ("http", "https"):
                base = f"{scheme}://{host}:{port}"
                result = self._probe_base(base)
                if result:
                    found.append(result)
                    logger.info("Found LLM endpoint: %s (%s)", base, result.endpoint_type)

        self._discovered.extend(found)
        return found

    def scan_range(self, base_host: str, start: int = 1, end: int = 255) -> List[DiscoveredEndpoint]:
        """Scan a /24 subnet for LLM endpoints."""
        prefix = ".".join(base_host.split(".")[:3])
        all_found = []
        for i in range(start, end + 1):
            host = f"{prefix}.{i}"
            found = self.scan_host(host)
            all_found.extend(found)
        return all_found

    def _probe_base(self, base_url: str) -> Optional[DiscoveredEndpoint]:
        for path, ep_type in self.ENDPOINT_PROBES:
            url = base_url + path
            try:
                with httpx.Client(timeout=self.timeout, verify=False) as client:
                    resp = client.get(url)
                    if resp.status_code in (200, 401, 403, 405):
                        authenticated = resp.status_code in (401, 403)
                        models = self._extract_models(resp)
                        return DiscoveredEndpoint(
                            url=base_url,
                            endpoint_type=ep_type,
                            authenticated=authenticated,
                            models_available=models,
                            response_headers=dict(resp.headers),
                            fingerprint=self._fingerprint_response(resp),
                        )
            except Exception:
                pass
        return None

    def _extract_models(self, response: httpx.Response) -> List[str]:
        try:
            data = response.json()
            if isinstance(data, dict):
                # OpenAI /v1/models format
                if "data" in data:
                    return [m.get("id", "") for m in data["data"][:10]]
                # Ollama /api/tags format
                if "models" in data:
                    return [m.get("name", "") for m in data["models"][:10]]
        except Exception:
            pass
        return []

    def _fingerprint_response(self, response: httpx.Response) -> str:
        headers = dict(response.headers)
        server = headers.get("server", "")
        powered_by = headers.get("x-powered-by", "")
        if "openai" in str(response.text).lower():
            return "openai-compatible"
        if server:
            return f"server:{server}"
        if powered_by:
            return f"powered-by:{powered_by}"
        return "unknown"

    @property
    def discovered(self) -> List[DiscoveredEndpoint]:
        return list(self._discovered)

    def report(self) -> str:
        if not self._discovered:
            return "No LLM endpoints discovered."
        lines = [f"Discovered {len(self._discovered)} LLM endpoint(s):"]
        for ep in self._discovered:
            auth_str = " [AUTH REQUIRED]" if ep.authenticated else " [OPEN]"
            models_str = f" models={ep.models_available[:3]}" if ep.models_available else ""
            lines.append(f"  {ep.url} [{ep.endpoint_type}]{auth_str}{models_str}")
        return "\n".join(lines)
