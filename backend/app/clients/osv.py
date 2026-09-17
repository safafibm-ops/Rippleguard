"""
OSV.dev client - the vulnerability intelligence source.

OSV is free, needs no API key, aggregates GHSA/PyPA/RustSec/distro advisories,
and speaks package+version natively, so we never have to do our own CPE
matching. We use /v1/querybatch to keep a 300-package scan to a handful of
round trips, then /v1/vulns/{id} for the detail of only the advisories that
actually matched.

We never invent vulnerability data. If OSV is unreachable, the exploit channel
is reported as UNAVAILABLE in the UI and the blend reweights onto the trust
channel rather than silently scoring 0.
"""
from __future__ import annotations

import asyncio

from ..config import settings
from .base import fetcher

SOURCE = "osv"

_ECOSYSTEM = {"npm": "npm", "pypi": "PyPI", "maven": "Maven",
              "cargo": "crates.io", "go": "Go", "nuget": "NuGet"}


def _severity_from(vuln: dict) -> tuple[float, str, str]:
    """(cvss_score 0-10, label, source_string). OSV carries CVSS vectors in
    `severity`, and GHSA's coarse label in database_specific."""
    best = 0.0
    vector = ""
    for sev in vuln.get("severity") or []:
        score = sev.get("score", "")
        if sev.get("type", "").startswith("CVSS") and isinstance(score, str):
            vector = score
            parsed = _score_from_vector(score)
            if parsed is not None:
                best = max(best, parsed)
    label = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(label, str):
        label = label.upper()
    else:
        label = ""
    if best == 0.0 and label:
        best = {"CRITICAL": 9.3, "HIGH": 7.5, "MODERATE": 5.5,
                "MEDIUM": 5.5, "LOW": 3.0}.get(label, 0.0)
    if not label and best:
        label = ("CRITICAL" if best >= 9 else "HIGH" if best >= 7
                 else "MODERATE" if best >= 4 else "LOW")
    return round(best, 1), label or "UNKNOWN", vector


_CVSS_WEIGHTS_NOTE = (
    "OSV publishes CVSS vectors, not always the numeric score. We parse the "
    "base score when the vector carries it, otherwise we map the coarse "
    "severity label. Both paths are recorded in the evidence bundle."
)


def _score_from_vector(vector: str) -> float | None:
    """CVSS v3.x base score from a vector string.

    Implements the published v3.1 base equations. Worth the ~30 lines: it lets
    us rank advisories by real severity instead of by a three-bucket label.
    """
    if not vector.startswith(("CVSS:3.0", "CVSS:3.1")):
        return None
    parts = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[parts["AV"]]
        ac = {"L": 0.77, "H": 0.44}[parts["AC"]]
        ui = {"N": 0.85, "R": 0.62}[parts["UI"]]
        scope_changed = parts["S"] == "C"
        pr_map = {"N": 0.85, "L": 0.68 if scope_changed else 0.62,
                  "H": 0.50 if scope_changed else 0.27}
        pr = pr_map[parts["PR"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        c, i, a = cia[parts["C"]], cia[parts["I"]], cia[parts["A"]]
    except (KeyError, ValueError):
        return None

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = min((1.08 if scope_changed else 1.0) * (impact + exploitability), 10.0)
    # CVSS rounds UP to one decimal.
    return float(int(raw * 10 + 0.99999) / 10)


def _fixed_version(vuln: dict, ecosystem: str, name: str) -> str | None:
    """First `fixed` boundary OSV lists for this package. Drives the
    'upgrade' remediation option - we never guess a fix version."""
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("name") != name:
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    return ev["fixed"]
    return None


async def query_batch(packages: list[tuple[str, str, str]]) -> dict[str, list[dict]]:
    """packages = [(ecosystem, name, version)] -> {'name@version': [vuln ids]}"""
    if not packages:
        return {}
    out: dict[str, list[dict]] = {}
    chunk = 100
    for start in range(0, len(packages), chunk):
        batch = packages[start:start + chunk]
        payload = {"queries": [
            {"version": v, "package": {"name": n,
                                       "ecosystem": _ECOSYSTEM.get(eco, eco)}}
            for eco, n, v in batch
        ]}
        data = await fetcher.post_json(
            SOURCE, f"{settings.osv_api}/v1/querybatch", payload
        )
        if not isinstance(data, dict):
            continue
        for (eco, name, version), result in zip(batch, data.get("results") or []):
            vulns = result.get("vulns") or []
            if vulns:
                out[f"{name}@{version}"] = vulns
    return out


async def vuln_detail(vuln_id: str) -> dict | None:
    return await fetcher.get_json(SOURCE, f"{settings.osv_api}/v1/vulns/{vuln_id}")


async def enrich(packages: list[tuple[str, str, str]]) -> dict[str, list[dict]]:
    """Full advisory records keyed by 'name@version', normalised for scoring."""
    hits = await query_batch(packages)
    ids = sorted({v.get("id") for lst in hits.values() for v in lst if v.get("id")})
    details = await asyncio.gather(*(vuln_detail(i) for i in ids),
                                   return_exceptions=True)
    by_id = {}
    for vid, det in zip(ids, details):
        if isinstance(det, dict):
            by_id[vid] = det

    name_of = {f"{n}@{v}": n for _e, n, v in packages}
    eco_of = {f"{n}@{v}": e for e, n, v in packages}
    out: dict[str, list[dict]] = {}
    for key, lst in hits.items():
        records = []
        for stub in lst:
            vid = stub.get("id")
            det = by_id.get(vid) or stub
            score, label, vector = _severity_from(det)
            aliases = det.get("aliases") or []
            records.append({
                "id": vid,
                "aliases": aliases,
                "cve": next((a for a in aliases if a.startswith("CVE-")), None),
                "summary": (det.get("summary") or "").strip()[:280],
                "cvss": score,
                "severity_label": label,
                "cvss_vector": vector,
                "published": det.get("published"),
                "modified": det.get("modified"),
                "fixed_version": _fixed_version(det, eco_of.get(key, "npm"),
                                                name_of.get(key, "")),
                "references": [r.get("url") for r in (det.get("references") or [])][:5],
            })
        records.sort(key=lambda r: r["cvss"], reverse=True)
        out[key] = records
    return out
