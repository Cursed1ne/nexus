"""
NexusProxy — HTTP/S traffic interception for NEXUS scanner.

Two modes:

  1. External proxy  — route all scanner traffic through an already-running
                       proxy (Burp Suite, ZAP, mitmproxy, Charles, etc.)
       scan.py http://target --proxy-url http://127.0.0.1:8080

  2. Built-in proxy  — NEXUS starts mitmweb automatically, scanner traffic
                       flows through it, you watch it live in the browser.
       scan.py http://target --intercept
       → mitmproxy listener : http://127.0.0.1:8082
       → mitmweb UI         : http://127.0.0.1:8083

What you get:
  - Every HTTP request the scanner makes (crawl + all 65 checks) appears in
    the proxy UI with full headers and body.
  - You can modify a request, replay it, or block it before it reaches the
    target (Burp-style intercept tab).
  - All traffic is tagged with the NEXUS session ID so you can filter by scan.
  - SSL/TLS is terminated by the proxy (install its CA cert to avoid errors,
    or use --no-verify which is the default).

Requirements for built-in mode:
  pip install mitmproxy        # provides mitmweb binary
"""
from __future__ import annotations

import logging
import os
import shutil
import signal
import subprocess
import time
from typing import Optional

logger = logging.getLogger(__name__)

_DEFAULT_PROXY_PORT = 8082
_DEFAULT_WEB_PORT   = 8083


class NexusProxy:
    """Manages the lifecycle of a built-in mitmweb proxy process."""

    def __init__(
        self,
        proxy_port: int = _DEFAULT_PROXY_PORT,
        web_port: int = _DEFAULT_WEB_PORT,
    ):
        self.proxy_port = proxy_port
        self.web_port   = web_port
        self.proxy_url  = f"http://127.0.0.1:{proxy_port}"
        self._proc: Optional[subprocess.Popen] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> str:
        """
        Start mitmweb in the background.
        Returns the proxy URL string to pass to httpx clients.
        Raises RuntimeError if mitmproxy is not installed.
        """
        mitmweb = shutil.which("mitmweb")
        if not mitmweb:
            raise RuntimeError(
                "mitmproxy is not installed. Run:  pip install mitmproxy\n"
                "Then re-run with --intercept."
            )

        cmd = [
            mitmweb,
            "--listen-host", "127.0.0.1",
            "--listen-port", str(self.proxy_port),
            "--web-host",    "127.0.0.1",
            "--web-port",    str(self.web_port),
            "--no-web-open-browser",   # don't auto-open browser
            "--set", "ssl_insecure=true",  # allow untrusted target certs
        ]

        logger.info("[proxy] Starting mitmweb: %s", " ".join(cmd))
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,   # own process group for clean kill
        )

        # Give it a moment to bind the port
        time.sleep(1.5)

        if self._proc.poll() is not None:
            raise RuntimeError(
                f"mitmweb failed to start (exit {self._proc.returncode}). "
                f"Try: mitmweb --listen-port {self.proxy_port} --web-port {self.web_port}"
            )

        logger.info("[proxy] mitmweb running — proxy=%s  web-ui=http://127.0.0.1:%d",
                    self.proxy_url, self.web_port)
        return self.proxy_url

    def stop(self):
        """Terminate the mitmweb process and its process group."""
        if self._proc and self._proc.poll() is None:
            try:
                os.killpg(os.getpgid(self._proc.pid), signal.SIGTERM)
                self._proc.wait(timeout=5)
                logger.info("[proxy] mitmweb stopped")
            except Exception as exc:
                logger.debug("[proxy] Stop error: %s", exc)
            finally:
                self._proc = None

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_):
        self.stop()


# ---------------------------------------------------------------------------
# Helper — resolve proxy URL from CLI/API flags
# ---------------------------------------------------------------------------

def resolve_proxy(
    proxy_url: Optional[str] = None,
    intercept: bool = False,
    proxy_port: int = _DEFAULT_PROXY_PORT,
    web_port: int = _DEFAULT_WEB_PORT,
) -> tuple[Optional[str], Optional[NexusProxy]]:
    """
    Returns (proxy_url_string, NexusProxy_instance_or_None).

    proxy_url_string is passed directly to httpx AsyncClient(proxy=...).
    NexusProxy instance is returned so the caller can stop it after the scan.

    Usage:
        proxy_url, proxy_mgr = resolve_proxy(intercept=True)
        try:
            ... run scan with proxy_url ...
        finally:
            if proxy_mgr:
                proxy_mgr.stop()
    """
    if proxy_url:
        # External proxy — nothing to start
        logger.info("[proxy] Using external proxy: %s", proxy_url)
        return proxy_url, None

    if intercept:
        mgr = NexusProxy(proxy_port=proxy_port, web_port=web_port)
        url = mgr.start()
        return url, mgr

    return None, None
