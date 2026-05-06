"""
ScanContext — shared state across all checks within a single scan session.

Holds:
  - base_url             : target base URL
  - found_credentials    : credentials discovered by any check (hardcoded, brute-forced)
  - active_sessions      : valid auth tokens / cookies ready for use
  - login_endpoints      : discovered login form endpoints {url, method, user_field, pass_field}
  - wordlist_users       : loaded username list (from --userlist or --wordlist)
  - wordlist_passwords   : loaded password list (from --passlist or --wordlist)

Pattern: module-level singleton reset by CheckRunner at the start of each scan.
Checks import `get_ctx()` to read / write shared state without touching the call signature.
"""
from dataclasses import dataclass, field


@dataclass
class FoundCredential:
    username: str
    password: str
    source: str       # "hardcoded-html", "hardcoded-js", "brute-force", "sqli-dump"
    context: str = "" # URL / field / form where found


@dataclass
class ActiveSession:
    token: str = ""
    cookie: str = ""
    auth_type: str = ""   # "bearer", "cookie", "basic"
    base_url: str = ""
    credential: FoundCredential | None = None
    # Pre-built headers to inject into every authenticated request.
    # Populated by SessionAuthenticator so checks don't need to reconstruct them.
    extra_headers: dict = field(default_factory=dict)


@dataclass
class LoginEndpoint:
    url: str
    method: str = "POST"
    user_field: str = "username"
    pass_field: str = "password"
    content_type: str = "form"   # "form" | "json"
    extra_fields: dict = field(default_factory=dict)


@dataclass
class ScanContext:
    base_url: str = ""
    found_credentials: list[FoundCredential] = field(default_factory=list)
    active_sessions: list[ActiveSession] = field(default_factory=list)
    login_endpoints: list[LoginEndpoint] = field(default_factory=list)
    wordlist_users: list[str] = field(default_factory=list)
    wordlist_passwords: list[str] = field(default_factory=list)

    def add_credential(self, username: str, password: str, source: str, context: str = ""):
        """Record a discovered credential (deduplicates)."""
        for c in self.found_credentials:
            if c.username == username and c.password == password:
                return
        self.found_credentials.append(FoundCredential(
            username=username, password=password, source=source, context=context
        ))

    def add_session(self, session: ActiveSession):
        self.active_sessions.append(session)

    def add_login_endpoint(self, ep: LoginEndpoint):
        for e in self.login_endpoints:
            if e.url == ep.url:
                return
        self.login_endpoints.append(ep)

    def best_session(self) -> ActiveSession | None:
        return self.active_sessions[0] if self.active_sessions else None

    def auth_headers(self) -> dict:
        """Return Authorization / Cookie headers from the best active session."""
        s = self.best_session()
        if not s:
            return {}
        # Prefer pre-built headers from SessionAuthenticator (includes extra_headers)
        if s.extra_headers:
            return s.extra_headers
        # Fallback: reconstruct from fields
        if s.auth_type == "bearer" and s.token:
            return {"Authorization": f"Bearer {s.token}"}
        if s.auth_type == "cookie" and s.cookie:
            return {"Cookie": s.cookie}
        if s.auth_type == "basic" and s.token:
            return {"Authorization": f"Basic {s.token}"}
        return {}


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_ctx = ScanContext()


def get_ctx() -> ScanContext:
    return _ctx


def reset_ctx(
    base_url: str = "",
    injected_session: "ActiveSession | None" = None,
) -> ScanContext:
    """Called by CheckRunner at the start of every scan.

    If injected_session is provided (from the API auth config), it is seeded
    into the context immediately so all checks start authenticated.
    """
    global _ctx
    _ctx = ScanContext(base_url=base_url)
    if injected_session is not None:
        _ctx.add_session(injected_session)
    return _ctx
