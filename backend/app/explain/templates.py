"""
Deterministic explanation generator.

This runs ALWAYS. The LLM is optional and only ever rewrites this text into
prose - it never supplies a fact. If the LLM is disabled or unreachable, the
user still gets a complete, evidence-backed explanation.
"""
from __future__ import annotations


def explain_finding(finding: dict, simulation: dict | None = None) -> dict:
    name = f'{finding["name"]}@{finding["version"]}'
    reasons: list[str] = []

    vulns = finding["exploit"].get("vulnerabilities") or []
    if vulns:
        worst = vulns[0]
        reasons.append(
            f'Affected by {worst["id"]}'
            + (f' ({worst["cve"]})' if worst.get("cve") else "")
            + f', CVSS {worst.get("cvss")} {worst.get("severity_label", "")}'
            + (f', fixed in {worst["fixed_version"]}' if worst.get("fixed_version")
               else ', no fixed version published')
            + "."
        )
    else:
        reasons.append("No OSV advisory matches this exact version.")

    r = finding.get("reachability", {})
    reasons.append(
        f'Reachability: {r.get("state")} - {r.get("explanation")}'
        + (f' (seen in {", ".join(r.get("evidence", [])[:2])})'
           if r.get("evidence") else "")
        + "."
    )

    t = finding["trust"]
    reasons.append(
        f'Declared as "{t.get("declared_spec")}" ({t.get("range_kind")}), so a '
        f'malicious publish has an inheritance exposure of '
        f'{t.get("inheritance_exposure")}.'
    )
    if t.get("has_install_hook"):
        reasons.append(
            f'Executes {", ".join(t.get("install_scripts") or ["an install script"])} '
            f'during install - that code runs whether or not your application '
            f'ever imports this package.'
        )
    if t.get("maintainers"):
        reasons.append(
            f'Publishable by {len(t["maintainers"])} identity/identities: '
            f'{", ".join(t["maintainers"][:4])}.'
        )

    m = finding.get("metrics", {})
    reasons.append(
        f'Structurally: depth {m.get("depth")}, {m.get("in_app_dependents")} '
        f'dependents inside this application'
        + (f', {m.get("ecosystem_dependents"):,} across the registry'
           if m.get("ecosystem_dependents") else "")
        + f', PageRank share {m.get("pagerank_normalised")}.'
    )

    if simulation:
        reasons.append(
            f'Simulated compromise reaches {simulation["reached_packages"]} '
            f'package(s) and {simulation["reached_applications"]} application(s) '
            f'at depth {simulation["max_propagation_depth"]}, blast radius '
            f'{simulation["blast_radius"]["score"]}/100.'
        )

    verdict = _verdict(finding)
    return {
        "package": name,
        "verdict": verdict,
        "reasons": reasons,
        "score": finding["rippleguard_score"],
        "arithmetic": finding["score_breakdown"],
        "generated_by": "deterministic template (no model involved)",
    }


def _verdict(finding: dict) -> str:
    ex, tr = finding["exploit_score"], finding["trust_score"]
    vulns = finding["exploit"].get("vulnerabilities") or []
    if tr > ex + 15 and not vulns:
        return ("Risk here is in the publishing path, not in a catalogued "
                "vulnerability. A CVSS-first tool would not surface this package "
                "at all.")
    if tr > ex + 15:
        return ("Trust-channel exposure exceeds the exploit-channel score: the "
                "faster win is pinning and disabling install scripts, not "
                "waiting for a patch.")
    if ex > tr + 15:
        return ("A known vulnerability dominates here. Upgrading to the fixed "
                "version is the correct first action.")
    return "Both channels contribute materially; see the breakdown."


def evidence_bundle(finding: dict, simulation: dict | None) -> dict:
    """Exactly what the LLM is allowed to see. Nothing else."""
    bundle = {
        "package": f'{finding["name"]}@{finding["version"]}',
        "rippleguard_score": finding["rippleguard_score"],
        "score_arithmetic": finding["score_breakdown"],
        "exploit_channel": {
            "score": finding["exploit_score"],
            "components": finding["exploit"]["components"],
            "advisories": [
                {k: v.get(k) for k in ("id", "cve", "cvss", "severity_label",
                                       "summary", "fixed_version")}
                for v in (finding["exploit"].get("vulnerabilities") or [])
            ],
        },
        "trust_channel": {
            "score": finding["trust_score"],
            "components": finding["trust"]["components"],
            "inheritance_exposure": finding["trust"].get("inheritance_exposure"),
            "declared_spec": finding["trust"].get("declared_spec"),
            "install_scripts": finding["trust"].get("install_scripts"),
            "maintainers": finding["trust"].get("maintainers"),
        },
        "structural": finding.get("metrics"),
        "reachability": finding.get("reachability"),
    }
    if simulation:
        bundle["simulation"] = {
            "reached_packages": simulation["reached_packages"],
            "reached_applications": simulation["reached_applications"],
            "max_depth": simulation["max_propagation_depth"],
            "blast_radius": simulation["blast_radius"],
            "top_paths": [
                {"target": p["target_label"], "exposure": p["exposure"],
                 "steps": [s["label"] for s in p["steps"]]}
                for p in simulation["top_paths"][:3]
            ],
        }
    return bundle
