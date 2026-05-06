"""
POST /api/scan       — start a new scan
GET  /api/scan/{id}  — poll status + findings summary
GET  /api/scans      — list all sessions

Auth modes (optional — omit for unauthenticated scan):

  Paste session (fastest — copy from browser DevTools):
    { "auth": { "session_cookie": "connect.sid=s%3Aabc..." } }
    { "auth": { "bearer_token": "eyJhbGci..." } }

  Form / JSON login:
    { "auth": { "login_url": "http://target/login",
                "username": "user@example.com", "password": "s3cr3t",
                "user_field": "email", "pass_field": "password",
                "content_type": "json", "token_path": "authentication.token" } }

  Login + TOTP second factor:
    { "auth": { "login_url": "...", "username": "...", "password": "...",
                "totp_secret": "JBSWY3DPEHPK3PXP",
                "otp_url": "http://target/verify-otp", "otp_field": "token" } }

  OAuth 2.0 ROPC (API-first apps):
    { "auth": { "oauth_token_url": "https://auth.example.com/oauth/token",
                "client_id": "my-app", "client_secret": "xxx",
                "oauth_username": "user", "oauth_password": "pass",
                "oauth_scope": "openid profile" } }
"""
import asyncio
import logging
import uuid
from datetime import datetime
from typing import Optional

import httpx
from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

import db
from nexus.crawler.crawler import Crawler
from nexus.engine.authenticator import AuthConfig, SessionAuthenticator
from nexus.engine.check_runner import CheckRunner
from nexus.models import ScanSession, ScanStatus

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["scan"])

# In-memory task tracking (background coroutines per session)
_running: dict[str, asyncio.Task] = {}


class AuthConfigRequest(BaseModel):
    """All fields optional — only populate what you need for your auth method."""
    # Mode A: paste session
    session_cookie: str = ""
    bearer_token: str = ""
    # Mode B/C: form/JSON login
    login_url: str = ""
    username: str = ""
    password: str = ""
    user_field: str = "email"
    pass_field: str = "password"
    content_type: str = "json"
    token_path: str = "token"
    cookie_name: str = ""
    # Mode C: OTP/TOTP
    totp_secret: str = ""
    otp_code: str = ""
    otp_url: str = ""
    otp_field: str = "otp"
    # Mode D: OAuth ROPC
    oauth_token_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    oauth_username: str = ""
    oauth_password: str = ""
    oauth_scope: str = ""
    # Extra headers to inject on every request
    extra_headers: dict = {}


class ScanRequest(BaseModel):
    url: str
    max_pages: int = 50
    hitl_mode: bool = False
    auth: Optional[AuthConfigRequest] = None  # omit for unauthenticated scan
    # Proxy settings — omit for direct connection
    # proxy_url: route all scanner traffic through an external proxy (Burp/ZAP/mitmproxy)
    # Example: "http://127.0.0.1:8080"
    proxy_url: Optional[str] = None
    # Dirsearch / path discovery options
    dirsearch_wordlist: Optional[list[str]] = None     # extra paths to probe
    dirsearch_extensions: Optional[list[str]] = None   # e.g. [".php", ".bak"]
    dirsearch_recurse: int = 1                         # 0 = no recursion


class ScanResponse(BaseModel):
    session_id: str
    status: str
    message: str


@router.post("/scan", response_model=ScanResponse, status_code=202)
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    session_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()

    # Summarise auth mode for the session record
    auth_mode = _describe_auth(req.auth)

    session = ScanSession(
        id=session_id,
        target_url=req.url,
        status=ScanStatus.PENDING,
        created_at=now,
        updated_at=now,
        max_pages=req.max_pages,
        hitl_mode=req.hitl_mode,
    )
    db.create_session(session)

    background_tasks.add_task(
        _run_scan, session, req.auth, req.proxy_url,
        req.dirsearch_wordlist, req.dirsearch_extensions, req.dirsearch_recurse,
    )
    return ScanResponse(
        session_id=session_id,
        status=ScanStatus.PENDING.value,
        message=f"Scan started ({auth_mode}). Poll /api/scan/{session_id} for status.",
    )


def _describe_auth(auth: Optional[AuthConfigRequest]) -> str:
    if not auth:
        return "unauthenticated"
    if auth.bearer_token:
        return "pre-supplied Bearer token"
    if auth.session_cookie:
        return "pre-supplied session cookie"
    if auth.oauth_token_url:
        return "OAuth 2.0 ROPC"
    if auth.login_url and (auth.totp_secret or auth.otp_code):
        return "login + OTP/TOTP"
    if auth.login_url:
        return "form/JSON login"
    return "unauthenticated"


@router.get("/scan/{session_id}")
async def get_scan(session_id: str):
    session = db.get_session(session_id)
    if not session:
        raise HTTPException(404, f"Session {session_id!r} not found")

    findings = db.list_findings(session_id=session_id)
    return {
        **session.to_dict(),
        "findings": [f.to_dict() for f in findings],
    }


@router.get("/scans")
async def list_scans(limit: int = 20):
    sessions = db.list_sessions(limit=limit)
    return [s.to_dict() for s in sessions]


# ---------------------------------------------------------------------------
# Background scan orchestration
# ---------------------------------------------------------------------------

async def _run_scan(
    session: ScanSession,
    auth_req: Optional[AuthConfigRequest] = None,
    proxy_url: Optional[str] = None,
    dirsearch_wordlist: Optional[list[str]] = None,
    dirsearch_extensions: Optional[list[str]] = None,
    dirsearch_recurse: int = 1,
):
    try:
        # ---- Phase 0: Resolve authentication ----
        injected_session = None
        auth_headers: dict = {}

        if auth_req:
            cfg = AuthConfig(
                session_cookie=auth_req.session_cookie,
                bearer_token=auth_req.bearer_token,
                login_url=auth_req.login_url,
                username=auth_req.username,
                password=auth_req.password,
                user_field=auth_req.user_field,
                pass_field=auth_req.pass_field,
                content_type=auth_req.content_type,
                token_path=auth_req.token_path,
                cookie_name=auth_req.cookie_name,
                totp_secret=auth_req.totp_secret,
                otp_code=auth_req.otp_code,
                otp_url=auth_req.otp_url,
                otp_field=auth_req.otp_field,
                oauth_token_url=auth_req.oauth_token_url,
                client_id=auth_req.client_id,
                client_secret=auth_req.client_secret,
                oauth_username=auth_req.oauth_username,
                oauth_password=auth_req.oauth_password,
                oauth_scope=auth_req.oauth_scope,
                extra_headers=auth_req.extra_headers,
            )
            async with httpx.AsyncClient(
                follow_redirects=True, timeout=20.0, verify=False
            ) as auth_client:
                injected_session = await SessionAuthenticator().resolve(cfg, auth_client)

            if injected_session:
                auth_headers = injected_session.extra_headers
                logger.info("[%s] Auth resolved — type=%s",
                            session.id, injected_session.auth_type)
            else:
                logger.warning("[%s] Auth config provided but login failed — "
                               "scanning unauthenticated", session.id)

        # ---- Phase 1: Crawl ----
        session.status = ScanStatus.CRAWLING
        db.update_session(session)
        logger.info("[%s] Crawling %s", session.id, session.target_url)

        if proxy_url:
            logger.info("[%s] Proxy enabled: %s", session.id, proxy_url)

        crawler = Crawler(
            target_url=session.target_url,
            max_pages=session.max_pages,
            extra_headers=auth_headers,
            auth_token=injected_session.token if injected_session else None,
            proxy_url=proxy_url,
        )
        crawl_results, insertion_points = await crawler.crawl()
        session.pages_crawled = len(crawl_results)
        db.update_session(session)
        logger.info(
            "[%s] Crawl complete: %d pages, %d insertion points",
            session.id, len(crawl_results), len(insertion_points),
        )

        # ---- Phase 2: Audit ----
        session.status = ScanStatus.AUDITING
        db.update_session(session)

        def _on_finding(finding):
            db.save_finding(finding)
            session.findings_count += 1
            db.update_session(session)

        runner = CheckRunner(
            session_id=session.id,
            on_finding=_on_finding,
            injected_session=injected_session,
            proxy_url=proxy_url,
            dirsearch_wordlist=dirsearch_wordlist,
            dirsearch_extensions=dirsearch_extensions or [],
            dirsearch_recurse=dirsearch_recurse,
        )
        await runner.run(crawl_results, insertion_points)

        session.status = ScanStatus.COMPLETE
        db.update_session(session)
        logger.info("[%s] Scan complete — %d findings", session.id, session.findings_count)

    except Exception as exc:
        logger.exception("[%s] Scan failed: %s", session.id, exc)
        session.status = ScanStatus.ERROR
        session.error = str(exc)
        db.update_session(session)
