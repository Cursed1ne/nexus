"""
CVSS 3.1 base score calculator (stub — full implementation in Phase 5).
"""


def base_score(
    av: str = "N",   # Attack Vector: N/A/L/P
    ac: str = "L",   # Attack Complexity: L/H
    pr: str = "N",   # Privileges Required: N/L/H
    ui: str = "N",   # User Interaction: N/R
    s: str = "U",    # Scope: U/C
    c: str = "H",    # Confidentiality: N/L/H
    i: str = "H",    # Integrity: N/L/H
    a: str = "H",    # Availability: N/L/H
) -> float:
    """Returns a CVSS 3.1 base score (0.0–10.0). Stub returns preset for Phase 1."""
    # Minimal table-based calculation
    _AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    _AC = {"L": 0.77, "H": 0.44}
    _PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
    _PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
    _UI = {"N": 0.85, "R": 0.62}
    _CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

    pr_val = (_PR_C if s == "C" else _PR_U).get(pr, 0.62)
    iss = 1 - (1 - _CIA.get(c, 0.56)) * (1 - _CIA.get(i, 0.56)) * (1 - _CIA.get(a, 0.56))

    if s == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * _AV.get(av, 0.85) * _AC.get(ac, 0.77) * pr_val * _UI.get(ui, 0.85)

    if s == "U":
        raw = min(impact + exploitability, 10)
    else:
        raw = min(1.08 * (impact + exploitability), 10)

    # Round up to nearest 0.1
    import math
    return math.ceil(raw * 10) / 10
