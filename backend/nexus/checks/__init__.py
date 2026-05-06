from .base import BaseScanCheck
from .sqli import SqliErrorCheck, SqliTimeCheck, SqliAuthBypassCheck, SqliUnionCheck, SqliBooleanCheck
from .xss import XssReflectedCheck
from .ssti import SstiCheck, SstiGenericCheck, SstiProfileCheck
from .traversal import PathTraversalCheck, DirectoryDisclosureCheck
from .passive import (
    MissingSecurityHeadersCheck,
    OpenRedirectCheck,
    CorsCheck,
    InformationDisclosureCheck,
    DirectoryListingCheck,
)
from .ssrf_jwt import SsrfCheck, JwtUnsignedCheck
from .static_analysis import StaticJsAnalysisCheck
from .admin_chain import AdminChainCheck
from .nosql import NoSqlLoginBypassCheck, NoSqlReviewsCheck
from .idor import IdorBasketCheck
from .xxe import XxeB2bCheck
from .stored_xss import StoredXssReviewCheck, StoredXssFeedbackCheck, StoredXssProfileCheck, StoredXssGuestbookCheck
from .advanced import (
    WeakPasswordHashCheck,
    AccountEnumerationCheck,
    PrototypePollutionCheck,
    HttpVerbTamperingCheck,
    CsrfCheck,
    RateLimitCheck,
)
from .cve_checks import (
    CommandInjectionCheck,
    CookieSecurityCheck,
    HostHeaderInjectionCheck,
    Log4ShellCheck,
    ShellshockCheck,
    SpringShellCheck,
    StrutsOgnlCheck,
    ComponentVersionCheck,
    GenericSsrfCheck,
    InsecureDeserCheck,
)
from .creds_checks import (
    HardcodedCredentialsCheck,
    LoginBruteforceCheck,
)
from .oauth_check import OAuthCheck
from .api_checks import (
    SsjsInjectionCheck,
    BolaCheck,
    BflaCheck,
    DebugEndpointCheck,
    SensitiveApiPathCheck,
    CommandInjectionExtCheck,
)
from .hacktricks import (
    CrlfInjectionCheck,
    MassAssignmentCheck,
    InsecureFileUploadCheck,
    ClickjackingCheck,
    OpenRedirectActiveCheck,
    PasswordResetPoisoningCheck,
    RaceConditionCheck,
    BusinessLogicCheck,
    GraphQlCheck,
    LdapInjectionCheck,
    HttpParamPollutionCheck,
    WebCachePoisoningCheck,
    SsiInjectionCheck,
    HttpSmugglingCheck,
    TwoFaBypassCheck,
    CsvInjectionCheck,
    CspBypassCheck,
)

# Full registry — ordered: passive first (no traffic), then active checks
ALL_CHECKS: list[BaseScanCheck] = [
    # ---- Passive (no extra requests, analyse what crawl returned) ----
    MissingSecurityHeadersCheck(),
    OpenRedirectCheck(),
    CorsCheck(),
    InformationDisclosureCheck(),
    DirectoryListingCheck(),
    DirectoryDisclosureCheck(),
    StaticJsAnalysisCheck(),        # Scan JS bundles for eval/RCE/secrets (library-aware)
    HardcodedCredentialsCheck(),    # Hardcoded passwords/secrets in HTML/JS source
    CookieSecurityCheck(),          # Cookie Secure/HttpOnly/SameSite flags
    ComponentVersionCheck(),        # Known-vulnerable versions (Log4j/Spring/Apache)

    # ---- Active — auth + admin chain (run early to get admin token) ----
    SqliAuthBypassCheck(),          # SQLi → admin JWT
    JwtUnsignedCheck(),             # alg=none → admin JWT
    AdminChainCheck(),              # Post-auth: dump users, config, keys, logs

    # ---- Active — credential discovery + brute force (run early to get session) ----
    LoginBruteforceCheck(),         # Brute force with wordlists → stores creds in ScanContext

    # ---- Active — crypto + account security ----
    WeakPasswordHashCheck(),        # MD5 hash detection + offline cracking
    AccountEnumerationCheck(),      # Username enumeration via response diff
    RateLimitCheck(),               # Missing rate limit → brute force possible

    # ---- Active — injection ----
    SqliErrorCheck(),               # DB error-based SQLi
    SqliUnionCheck(),               # UNION exfiltration + full DB dump
    NoSqlLoginBypassCheck(),        # MongoDB operator injection in login
    NoSqlReviewsCheck(),            # NoSQL injection in review PATCH
    XxeB2bCheck(),                  # XXE in B2B XML order endpoint
    PrototypePollutionCheck(),      # JavaScript __proto__ pollution
    CommandInjectionCheck(),        # OS command injection (timing + output)
    InsecureDeserCheck(),           # Java/PHP deserialization

    # ---- Active — client-side ----
    XssReflectedCheck(),            # Reflected XSS with canary
    StoredXssReviewCheck(),         # Stored XSS in product reviews
    StoredXssFeedbackCheck(),       # Stored XSS in customer feedback
    StoredXssProfileCheck(),        # Stored XSS in username/profile
    StoredXssGuestbookCheck(),      # Stored XSS in PHP guestbook/comment forms

    # ---- Active — server-side injection ----
    SstiProfileCheck(),             # Authenticated eval() RCE via username
    SstiGenericCheck(),             # Generic differential SSTI

    # ---- Active — access control + SSRF ----
    SsrfCheck(),                    # SSRF via profile image URL (Juice Shop)
    GenericSsrfCheck(),             # SSRF via any URL param (cloud metadata)
    IdorBasketCheck(),              # IDOR basket/order enumeration
    PathTraversalCheck(),           # LFI / directory traversal
    HttpVerbTamperingCheck(),       # HTTP method override bypass
    CsrfCheck(),                    # CSRF — missing protection on state changes
    HostHeaderInjectionCheck(),     # Host header injection / password reset poisoning

    # ---- Active — CVEs ----
    Log4ShellCheck(),               # CVE-2021-44228 JNDI injection in headers
    ShellshockCheck(),              # CVE-2014-6271 bash CGI env injection
    SpringShellCheck(),             # CVE-2022-22965 Spring classloader RCE
    StrutsOgnlCheck(),              # CVE-2017-5638 Struts2 OGNL injection

    # ---- Active — OAuth 2.0 attacks ----
    OAuthCheck(),                   # Missing state (CSRF), redirect_uri bypass, token leakage

    # ---- Active / Passive — HackTricks full coverage ----
    ClickjackingCheck(),            # Missing X-Frame-Options + frame-ancestors (passive)
    CrlfInjectionCheck(),           # CRLF → arbitrary response header injection
    MassAssignmentCheck(),          # Privileged field in registration (role=admin)
    InsecureFileUploadCheck(),      # Webshell upload + execution confirmation
    OpenRedirectActiveCheck(),      # Follow redirect chain to attacker domain
    PasswordResetPoisoningCheck(),  # Host header injection in password reset
    RaceConditionCheck(),           # Concurrent requests bypass rate limits
    BusinessLogicCheck(),           # Negative qty, coupon reuse, limit bypass
    GraphQlCheck(),                 # Introspection + IDOR + injection in args
    LdapInjectionCheck(),           # LDAP operator bypass in login
    HttpParamPollutionCheck(),      # Duplicate param → second value used
    WebCachePoisoningCheck(),       # Unkeyed header poisons CDN cache
    SsiInjectionCheck(),            # SSI exec in text inputs
    HttpSmugglingCheck(),           # CL.TE / TE.CL desync detection
    TwoFaBypassCheck(),             # OTP rate limit + direct access bypass
    CsvInjectionCheck(),            # CSV formula injection (DDE/Excel macro)
    CspBypassCheck(),               # CSP weakness + bypass domain detection (passive)

    # ---- Active — API-specific (SSJS, BOLA, BFLA, debug endpoints, CMDi-ext) ----
    SsjsInjectionCheck(),           # NodeGoat eval() in POST body fields
    BolaCheck(),                    # IDOR on REST API paths (VAmPI/Juice Shop/NodeGoat)
    BflaCheck(),                    # Broken function-level auth (VAmPI PUT /password)
    DebugEndpointCheck(),           # Exposed debug endpoints leaking credentials
    CommandInjectionExtCheck(),     # DVWA /exec + DVNA /ping command injection

    # ---- Passive — sensitive API path detection ----
    SensitiveApiPathCheck(),        # Detects debug/actuator paths in crawled pages

    # ---- Active — boolean blind SQLi ----
    SqliBooleanCheck(),             # Boolean-blind SQLi — TRUE/FALSE response diff

    # ---- Active — time-based (slow, run last) ----
    SqliTimeCheck(),
]

__all__ = [
    "BaseScanCheck",
    "HardcodedCredentialsCheck",
    "LoginBruteforceCheck",
    "SqliErrorCheck",
    "SqliTimeCheck",
    "SqliAuthBypassCheck",
    "SqliUnionCheck",
    "SsrfCheck",
    "JwtUnsignedCheck",
    "StaticJsAnalysisCheck",
    "AdminChainCheck",
    "NoSqlLoginBypassCheck",
    "NoSqlReviewsCheck",
    "IdorBasketCheck",
    "XxeB2bCheck",
    "XssReflectedCheck",
    "StoredXssReviewCheck",
    "StoredXssFeedbackCheck",
    "StoredXssProfileCheck",
    "WeakPasswordHashCheck",
    "AccountEnumerationCheck",
    "PrototypePollutionCheck",
    "HttpVerbTamperingCheck",
    "CsrfCheck",
    "RateLimitCheck",
    "SstiCheck",
    "SstiProfileCheck",
    "PathTraversalCheck",
    "DirectoryDisclosureCheck",
    "MissingSecurityHeadersCheck",
    "OpenRedirectCheck",
    "CorsCheck",
    "InformationDisclosureCheck",
    "DirectoryListingCheck",
    "StoredXssGuestbookCheck",
    # Phase 3 additions
    "CommandInjectionCheck",
    "CookieSecurityCheck",
    "HostHeaderInjectionCheck",
    "Log4ShellCheck",
    "ShellshockCheck",
    "SpringShellCheck",
    "StrutsOgnlCheck",
    "ComponentVersionCheck",
    "GenericSsrfCheck",
    "InsecureDeserCheck",
    "SqliBooleanCheck",
    "OAuthCheck",
    "SsjsInjectionCheck",
    "BolaCheck",
    "BflaCheck",
    "DebugEndpointCheck",
    "SensitiveApiPathCheck",
    "CommandInjectionExtCheck",
    "ALL_CHECKS",
]
