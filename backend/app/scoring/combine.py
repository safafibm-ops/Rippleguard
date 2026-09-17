"""
Combine the two channels into one ranking, and - the important bit - measure
where they DISAGREE.

`rank_inversion` is the headline demo artefact: the packages whose priority
changes most between a CVSS-only ranking and RippleGuard's trust channel. A
package with no CVE at all can top the trust ranking because it has an install
hook, floats on a caret range, and shares a publisher with hundreds of other
packages. That is the thing to put on the screen.
"""
from __future__ import annotations

from ..config import settings


def blend(exploit_score: float, trust_score: float, structural_score: float,
          osv_available: bool) -> tuple[float, list[dict], str]:
    """RippleGuard score with an itemised breakdown.

    If OSV is unreachable we do NOT silently score the exploit channel as 0 -
    that would understate risk and look like a clean bill of health. We
    reweight onto the remaining channels and say so.
    """
    w = settings.blend
    if osv_available:
        parts = [
            ("Exploit channel", w.exploit, exploit_score),
            ("Trust channel", w.trust, trust_score),
            ("Structural criticality", w.structural, structural_score),
        ]
        note = ""
    else:
        scale = 1.0 / (w.trust + w.structural)
        parts = [
            ("Trust channel", w.trust * scale, trust_score),
            ("Structural criticality", w.structural * scale, structural_score),
        ]
        note = ("OSV unreachable: the exploit channel could not be evaluated, so "
                "its weight was redistributed. This score is NOT a statement that "
                "no vulnerabilities exist.")

    breakdown = [
        {"factor": name, "weight": round(weight, 3), "value": round(value, 1),
         "points": round(weight * value, 1)}
        for name, weight, value in parts
    ]
    total = round(sum(b["points"] for b in breakdown), 1)
    return min(total, 100.0), breakdown, note


def rank_inversion(findings: list[dict], top: int = 12) -> dict:
    """Compare a CVSS-only ranking against the trust-channel ranking.

    Returns both orderings plus the movement per package, which is what the
    dashboard renders as two columns with connector lines.
    """
    # Mimic a CVSS-first tool: severity, then advisory count, then proximity.
    # Deliberately does NOT tie-break on the trust score - doing so would make
    # the two rankings collapse into one and hide the inversion we are measuring.
    by_cvss = sorted(
        findings,
        key=lambda f: (
            f["exploit"].get("worst_cvss") or 0.0,
            len(f["exploit"].get("vulnerabilities") or []),
            -(f["metrics"].get("depth") or 99),
        ),
        reverse=True,
    )
    by_trust = sorted(findings, key=lambda f: f["trust"]["score"], reverse=True)

    cvss_rank = {f["id"]: i + 1 for i, f in enumerate(by_cvss)}
    trust_rank = {f["id"]: i + 1 for i, f in enumerate(by_trust)}

    def row(f, rank_a, rank_b):
        return {
            "id": f["id"],
            "name": f["name"],
            "version": f["version"],
            "cvss": f["exploit"].get("worst_cvss") or 0.0,
            "trust_score": f["trust"]["score"],
            "exploit_score": f["exploit"]["score"],
            "cvss_rank": rank_a,
            "trust_rank": rank_b,
            "movement": rank_a - rank_b,
            "has_install_hook": bool(f["trust"].get("has_install_hook")),
            "range_kind": f["trust"].get("range_kind"),
            "vuln_count": len(f["exploit"].get("vulnerabilities") or []),
        }

    left = [row(f, cvss_rank[f["id"]], trust_rank[f["id"]]) for f in by_cvss[:top]]
    right = [row(f, cvss_rank[f["id"]], trust_rank[f["id"]]) for f in by_trust[:top]]

    biggest = sorted(
        (row(f, cvss_rank[f["id"]], trust_rank[f["id"]]) for f in findings),
        key=lambda r: r["movement"], reverse=True,
    )[:6]

    # The strongest single demo fact: a package with zero CVEs that still tops
    # the trust ranking.
    headline = next(
        (r for r in right if r["vuln_count"] == 0 and r["trust_rank"] <= 5), None
    )

    return {
        "by_cvss": left,
        "by_trust": right,
        "largest_upward_moves": biggest,
        "headline_inversion": headline,
        "explanation": (
            "Left column is how a CVSS-first tool would rank these packages. "
            "Right column is RippleGuard's trust channel. Packages that move up "
            "on the right are ones where the risk is in the publishing path, "
            "not in a catalogued vulnerability."
        ),
    }
