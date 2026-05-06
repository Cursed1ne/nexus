"""
auth_flow.py — Automatic registration and login flow for NEXUS scanner.

Handles:
  1. Discover registration form on target
  2. Auto-register a test account (nexustestXXXX@test.com / NexusTest123!)
  3. Auto-login and extract session cookie/token
  4. Fallback: ask user to register manually and paste credentials

When auto-registration succeeds, all subsequent scan requests use the
authenticated session, enabling testing of:
  - /userinfo.php, /secured/*, /profile, /account, /dashboard
  - Stored XSS (requires posting then reading back)
  - IDOR (access other users' data with own account)
  - Mass assignment, BOLA, privilege escalation
"""
from __future__ import annotations

import re
import time
import uuid
import logging
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse, urlencode

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class TestCredentials:
    """Credentials used for the test account."""
    username: str
    email: str
    password: str
    first_name: str = "Nexus"
    last_name: str = "Tester"
    phone: str = "5550001234"


@dataclass
class AuthSession:
    """Active authenticated session for the scanner."""
    credentials: TestCredentials
    cookies: dict[str, str] = field(default_factory=dict)
    token: str = ""
    extra_headers: dict[str, str] = field(default_factory=dict)
    login_url: str = ""
    user_id: str = ""
    authenticated: bool = False
    method: str = ""   # "auto" | "injected" | "manual"
    notes: str = ""

    def as_httpx_cookies(self) -> dict[str, str]:
        return dict(self.cookies)

    def auth_headers(self) -> dict[str, str]:
        h = dict(self.extra_headers)
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        return h


# ---------------------------------------------------------------------------
# Constants — common registration/login patterns
# ---------------------------------------------------------------------------

_REGISTER_PATHS = [
    "/signup", "/signup.php", "/register", "/register.php",
    "/newuser", "/secured/newuser.php", "/new_user.php",
    "/user/register", "/user/new", "/account/register",
    "/auth/register", "/auth/signup", "/api/register",
    "/api/Users", "/api/v1/register",
    # WordPress, CMS
    "/wp-register.php", "/wp-login.php?action=register",
]

_LOGIN_PATHS = [
    "/login", "/login.php", "/signin", "/signin.php",
    "/user/login", "/account/login", "/auth/login",
    "/rest/user/login", "/api/login", "/api/auth/login",
    # WordPress
    "/wp-login.php",
]

# Field name patterns for form fields
_EMAIL_FIELDS  = ["email", "mail", "uname", "username", "user", "login",
                  "tbusername", "tbEmail", "user_email"]
_PASS_FIELDS   = ["password", "pass", "passwd", "pwd", "tbpassword", "tbPass"]
_FNAME_FIELDS  = ["first_name", "fname", "firstname", "name", "uname"]
_LNAME_FIELDS  = ["last_name", "lname", "lastname", "surname"]
_PHONE_FIELDS  = ["phone", "tel", "mobile", "phonenumber", "uphone"]
_CONFIRM_FIELDS = ["password2", "confirm_password", "confirmpassword",
                   "password_confirmation", "pass2", "repassword", "tbpassword2"]


# ---------------------------------------------------------------------------
# Form discovery helpers
# ---------------------------------------------------------------------------

def _find_field(form: "BeautifulSoup", candidates: list[str]) -> Optional["BeautifulSoup"]:
    """Find an input field whose name/id matches any candidate (case-insensitive)."""
    for inp in form.find_all(["input", "select", "textarea"]):
        name = (inp.get("name") or inp.get("id") or "").lower()
        for c in candidates:
            if c.lower() in name or name in c.lower():
                return inp
    return None


def _form_action(form: "BeautifulSoup", base_url: str) -> str:
    action = form.get("action", "")
    if not action:
        return base_url
    return urljoin(base_url, action)


def _extract_hidden_fields(form: "BeautifulSoup") -> dict[str, str]:
    """Extract hidden input fields (CSRF tokens, etc.)."""
    hidden = {}
    for inp in form.find_all("input", {"type": "hidden"}):
        name = inp.get("name", "")
        val  = inp.get("value", "")
        if name:
            hidden[name] = val
    return hidden


# ---------------------------------------------------------------------------
# AuthFlowEngine — main class
# ---------------------------------------------------------------------------

class AuthFlowEngine:
    """
    Handles auto-registration → auto-login → session extraction.

    Usage::

        engine = AuthFlowEngine(base_url="http://testphp.vulnweb.com")
        session = await engine.run(client)
        if session.authenticated:
            # use session.cookies / session.auth_headers()
    """

    def __init__(
        self,
        base_url: str,
        timeout: float = 10.0,
        verbose: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verbose = verbose
        suffix = uuid.uuid4().hex[:6]
        self._creds = TestCredentials(
            username=f"nexus{suffix}",
            email=f"nexus{suffix}@nexustest.local",
            password=f"NexusTest{suffix}!",
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self, client: httpx.AsyncClient) -> AuthSession:
        """
        Full flow: discover → register → login.
        Returns an AuthSession (check .authenticated).
        """
        print(f"  [auth] Attempting auto-registration on {self.base_url}…", flush=True)

        # Step 1: find registration form
        reg_url, reg_form_data = await self._find_and_fill_registration(client)
        if reg_url and reg_form_data:
            registered = await self._submit_registration(client, reg_url, reg_form_data)
            if registered:
                print(f"  [auth] Registration succeeded as '{self._creds.username}'", flush=True)
                # Step 2: find login form and log in
                session = await self._find_and_login(client)
                if session.authenticated:
                    print(f"  [auth] Login succeeded — authenticated session active", flush=True)
                    return session
                else:
                    print(f"  [auth] Registration OK but login failed — trying direct login", flush=True)
                    session = await self._try_direct_login(client)
                    if session.authenticated:
                        return session

        print(f"  [auth] Auto-registration failed", flush=True)
        return AuthSession(credentials=self._creds, authenticated=False, method="auto", notes="auto-reg-failed")

    async def login_only(
        self,
        client: httpx.AsyncClient,
        username: str,
        password: str,
    ) -> AuthSession:
        """
        Login with provided credentials (no registration).
        Used when user supplies --username/--password or manual creds.
        """
        self._creds = TestCredentials(
            username=username,
            email=username,
            password=password,
        )
        session = await self._find_and_login(client)
        if session.authenticated:
            session.method = "injected"
        return session

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    async def _find_and_fill_registration(
        self, client: httpx.AsyncClient
    ) -> tuple[str, dict]:
        """
        Find the registration form. Returns (action_url, form_data_dict) or (None, None).
        Strategy:
          1. Try common registration paths
          2. Also scrape homepage for "signup"/"register" links
        """
        # Try to discover via homepage links first
        reg_link = await self._discover_link(client, ["sign", "register", "signup", "newuser", "create"])
        candidates = []
        if reg_link:
            candidates.append(reg_link)
        candidates += [self.base_url + p for p in _REGISTER_PATHS]

        for url in candidates:
            try:
                resp = await client.get(url)
                if resp.status_code not in (200, 301, 302):
                    continue
                # Follow redirects
                final_url = str(resp.url)
                html = resp.text
                soup = BeautifulSoup(html, "html.parser")

                # Find a form with password field
                for form in soup.find_all("form"):
                    if _find_field(form, _PASS_FIELDS):
                        action = _form_action(form, final_url)
                        data   = self._fill_registration_form(form)
                        if data:
                            logger.info("[auth] Registration form found at %s → POST %s", url, action)
                            return action, data
            except Exception as e:
                logger.debug("[auth] Registration probe %s: %s", url, e)

        return None, None

    def _fill_registration_form(self, form: "BeautifulSoup") -> Optional[dict]:
        """Fill a registration form with test credentials. Returns None if no password field."""
        data = {}

        # Hidden fields (CSRF tokens etc.)
        data.update(_extract_hidden_fields(form))

        # Password field required
        pass_inp = _find_field(form, _PASS_FIELDS)
        if not pass_inp:
            return None
        data[pass_inp.get("name", "password")] = self._creds.password

        # Username/email
        email_inp = _find_field(form, _EMAIL_FIELDS)
        if email_inp:
            name = email_inp.get("name", "email")
            # Detect whether email or username format is expected
            if "email" in (email_inp.get("type", "") + name).lower():
                data[name] = self._creds.email
            else:
                data[name] = self._creds.username

        # Confirm password
        confirm_inp = _find_field(form, _CONFIRM_FIELDS)
        if confirm_inp and confirm_inp != pass_inp:
            data[confirm_inp.get("name", "password2")] = self._creds.password

        # First/last name
        fname = _find_field(form, _FNAME_FIELDS)
        if fname:
            data[fname.get("name", "name")] = self._creds.first_name
        lname = _find_field(form, _LNAME_FIELDS)
        if lname:
            data[lname.get("name", "lastname")] = self._creds.last_name

        # Phone
        phone = _find_field(form, _PHONE_FIELDS)
        if phone:
            data[phone.get("name", "phone")] = self._creds.phone

        # Fill remaining required text fields with safe defaults
        for inp in form.find_all("input"):
            inp_name = inp.get("name", "")
            inp_type = inp.get("type", "text").lower()
            if not inp_name or inp_name in data:
                continue
            if inp_type in ("submit", "button", "image", "reset", "file"):
                continue
            if inp_type == "checkbox":
                data[inp_name] = inp.get("value", "on")
            elif inp_type == "radio":
                data[inp_name] = inp.get("value", "1")
            elif inp_type == "email":
                data[inp_name] = self._creds.email
            elif inp_type == "tel":
                data[inp_name] = self._creds.phone
            else:
                data[inp_name] = "testvalue"

        return data if data else None

    async def _submit_registration(
        self, client: httpx.AsyncClient, url: str, data: dict
    ) -> bool:
        """Submit registration form. Returns True if likely succeeded."""
        try:
            resp = await client.post(url, data=data,
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
            body = resp.text.lower()
            status = resp.status_code

            # Success indicators
            success_patterns = [
                "success", "registered", "account created", "welcome",
                "thank you", "login", "please log", "confirm"
            ]
            # Failure indicators
            fail_patterns = [
                "already exists", "already taken", "taken", "in use",
                "invalid", "error", "failed", "please fill"
            ]

            if status in (200, 201, 302, 301):
                # Check for failure
                for pat in fail_patterns:
                    if pat in body:
                        logger.debug("[auth] Registration response indicates failure: %s", pat)
                        # Could be "already exists" — still try to login
                        return True  # Try login anyway
                return True
            return False
        except Exception as e:
            logger.debug("[auth] Registration submit error: %s", e)
            return False

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------

    async def _find_and_login(self, client: httpx.AsyncClient) -> AuthSession:
        """Find login form/endpoint and log in with test credentials."""
        # Try to discover via homepage links
        login_link = await self._discover_link(client, ["login", "signin", "sign-in"])
        candidates = []
        if login_link:
            candidates.append(login_link)
        candidates += [self.base_url + p for p in _LOGIN_PATHS]

        for url in candidates:
            try:
                resp = await client.get(url)
                if resp.status_code not in (200,):
                    continue
                final_url = str(resp.url)
                soup = BeautifulSoup(resp.text, "html.parser")

                for form in soup.find_all("form"):
                    if _find_field(form, _PASS_FIELDS):
                        action = _form_action(form, final_url)
                        data = self._fill_login_form(form)
                        if data:
                            session = await self._submit_login(client, action, data, url)
                            if session.authenticated:
                                session.login_url = url
                                return session
            except Exception as e:
                logger.debug("[auth] Login probe %s: %s", url, e)

        # Try JSON login (REST API style)
        for path in ["/rest/user/login", "/api/login", "/api/auth/login", "/api/v1/auth/login"]:
            session = await self._try_json_login(client, self.base_url + path)
            if session.authenticated:
                return session

        return AuthSession(credentials=self._creds, authenticated=False, method="auto")

    def _fill_login_form(self, form: "BeautifulSoup") -> Optional[dict]:
        """Fill login form. Returns None if missing required fields."""
        data = {}
        data.update(_extract_hidden_fields(form))

        pass_inp = _find_field(form, _PASS_FIELDS)
        if not pass_inp:
            return None
        data[pass_inp.get("name", "password")] = self._creds.password

        email_inp = _find_field(form, _EMAIL_FIELDS)
        if email_inp:
            name = email_inp.get("name", "username")
            # Prefer username over email for login
            data[name] = self._creds.username

        return data if len(data) >= 2 else None

    async def _submit_login(
        self, client: httpx.AsyncClient, url: str, data: dict, login_page: str
    ) -> AuthSession:
        """Submit login form and extract session."""
        session = AuthSession(credentials=self._creds, authenticated=False, method="auto")
        try:
            resp = await client.post(url, data=data,
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
            body = resp.text.lower()
            status = resp.status_code

            # Success: redirect away from login page, or body has welcome message
            is_redirect = status in (301, 302)
            location = resp.headers.get("location", "")
            went_home = bool(location) and "login" not in location.lower()

            success_patterns = ["welcome", "logout", "my account", "dashboard",
                                 "profile", "sign out", "log out", self._creds.username.lower()]
            fail_patterns    = ["invalid", "incorrect", "wrong password", "failed",
                                 "not found", "error", "please try again"]

            has_success = any(p in body for p in success_patterns)
            has_fail    = any(p in body for p in fail_patterns)

            if (is_redirect and went_home) or (has_success and not has_fail) or status in (200,):
                if not has_fail:
                    # Extract cookies
                    session.cookies = dict(resp.cookies)
                    if not session.cookies and hasattr(client, "_cookies"):
                        session.cookies = dict(client.cookies)
                    session.authenticated = bool(session.cookies) or is_redirect or has_success
        except Exception as e:
            logger.debug("[auth] Login submit error: %s", e)
        return session

    async def _try_json_login(
        self, client: httpx.AsyncClient, url: str
    ) -> AuthSession:
        """Try JSON API login."""
        session = AuthSession(credentials=self._creds, authenticated=False, method="auto")
        payloads = [
            {"email": self._creds.email, "password": self._creds.password},
            {"username": self._creds.username, "password": self._creds.password},
            {"uname": self._creds.username, "pass": self._creds.password},
        ]
        for payload in payloads:
            try:
                resp = await client.post(url, json=payload)
                if resp.status_code in (200, 201):
                    body = resp.text.lower()
                    if any(k in body for k in ["token", "session", "auth", "bearer"]):
                        data = resp.json() if "application/json" in resp.headers.get("content-type", "") else {}
                        token = (data.get("token") or data.get("accessToken") or
                                 data.get("access_token") or "")
                        session.token = token
                        session.cookies = dict(resp.cookies)
                        session.authenticated = bool(token or session.cookies)
                        if session.authenticated:
                            return session
            except Exception:
                pass
        return session

    async def _try_direct_login(self, client: httpx.AsyncClient) -> AuthSession:
        """Try login directly without form discovery."""
        session = AuthSession(credentials=self._creds, authenticated=False, method="auto")
        for path in _LOGIN_PATHS[:5]:  # Try top 5
            try:
                url = self.base_url + path
                data = {
                    "username": self._creds.username,
                    "email": self._creds.email,
                    "password": self._creds.password,
                    "uname": self._creds.username,
                    "pass": self._creds.password,
                    "tbUsername": self._creds.username,
                    "tbPassword": self._creds.password,
                }
                resp = await client.post(url, data=data)
                if resp.status_code in (200, 302):
                    session.cookies = dict(resp.cookies)
                    if session.cookies:
                        session.authenticated = True
                        session.login_url = url
                        return session
            except Exception:
                pass
        return session

    # ------------------------------------------------------------------
    # Helper: discover links on homepage
    # ------------------------------------------------------------------

    async def _discover_link(
        self, client: httpx.AsyncClient, keywords: list[str]
    ) -> Optional[str]:
        """Scan homepage for links containing any keyword."""
        try:
            resp = await client.get(self.base_url + "/")
            soup = BeautifulSoup(resp.text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"].lower()
                text = a.get_text(strip=True).lower()
                for kw in keywords:
                    if kw in href or kw in text:
                        return urljoin(self.base_url, a["href"])
        except Exception:
            pass
        return None


# ---------------------------------------------------------------------------
# Manual registration prompt
# ---------------------------------------------------------------------------

def print_manual_registration_guide(base_url: str, creds: TestCredentials):
    """
    Print instructions for manual registration when auto-registration fails.
    Called during scan to ask the user to create an account.
    """
    print()
    print("─" * 72)
    print("  ⚠️  MANUAL REGISTRATION REQUIRED")
    print("─" * 72)
    print(f"  Auto-registration failed on {base_url}")
    print()
    print("  Please register a test account manually:")
    print(f"    1. Open {base_url} in your browser")
    print(f"    2. Navigate to the registration/signup page")
    print(f"    3. Create an account with these credentials:")
    print(f"         Username : {creds.username}")
    print(f"         Email    : {creds.email}")
    print(f"         Password : {creds.password}")
    print()
    print("  Then re-run the scan with --username and --password:")
    print(f"    python3 scan.py {base_url} \\")
    print(f"      --username {creds.username} \\")
    print(f"      --password {creds.password}")
    print()
    print("  OR paste your session cookie with --cookie 'PHPSESSID=xxx...'")
    print("─" * 72)
    print()


async def run_auth_flow(
    base_url: str,
    client: httpx.AsyncClient,
    verbose: bool = False,
    # Pre-supplied credentials override auto-registration
    injected_username: Optional[str] = None,
    injected_password: Optional[str] = None,
) -> Optional[AuthSession]:
    """
    Top-level function called from scan.py.
    Returns authenticated AuthSession or None if all methods fail.
    """
    engine = AuthFlowEngine(base_url=base_url, verbose=verbose)

    # If user supplied credentials, just login
    if injected_username and injected_password:
        session = await engine.login_only(client, injected_username, injected_password)
        if session.authenticated:
            return session
        print(f"  [auth] Supplied credentials failed to authenticate", flush=True)
        return None

    # Auto-register + login
    session = await engine.run(client)
    if session.authenticated:
        return session

    # Print manual registration guide
    print_manual_registration_guide(base_url, engine._creds)
    return None
