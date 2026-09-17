"""
deps.dev client (Google Open Source Insights).

Two things we use it for:
  * GetDependencies - a *resolved* dependency graph for a package version.
    This is the authoritative resolution for npm/PyPI/Maven/Cargo and saves us
    from re-implementing four resolvers.
  * GetDependents - a COUNT of distinct packages known to depend on a version.

Important limitation we surface in the UI: deps.dev's dependents endpoint
returns only a count, not the list. Google's own docs say the counts should be
treated as indicative of relative popularity rather than precisely accurate.
For the actual downstream package *list* we use ecosyste.ms instead.
"""
from __future__ import annotations

import asyncio
from urllib.parse import quote

from ..config import settings
from .base import fetcher

SOURCE = "deps.dev"

_SYSTEM = {"npm": "npm", "pypi": "pypi", "maven": "maven",
           "cargo": "cargo", "go": "go", "nuget": "nuget"}


def _url(eco: str, name: str, version: str, verb: str) -> str:
    return (f"{settings.depsdev_api}/v3alpha/systems/{_SYSTEM.get(eco, eco)}"
            f"/packages/{quote(name, safe='')}/versions/{quote(version, safe='')}"
            f":{verb}")


async def resolved_dependencies(eco: str, name: str, version: str) -> dict | None:
    """Resolved dependency graph: {'nodes': [...], 'edges': [...]}."""
    return await fetcher.get_json(SOURCE, _url(eco, name, version, "dependencies"))


async def dependent_count(eco: str, name: str, version: str) -> dict | None:
    """{'dependentCount': n, 'directDependentCount': n, 'indirectDependentCount': n}"""
    return await fetcher.get_json(SOURCE, _url(eco, name, version, "dependents"))


async def bulk_dependent_counts(
    triples: list[tuple[str, str, str]]
) -> dict[str, dict]:
    results = await asyncio.gather(
        *(dependent_count(e, n, v) for e, n, v in triples), return_exceptions=True
    )
    out: dict[str, dict] = {}
    for (_e, n, v), res in zip(triples, results):
        if isinstance(res, dict):
            out[f"{n}@{v}"] = {
                "total": int(res.get("dependentCount") or 0),
                "direct": int(res.get("directDependentCount") or 0),
                "indirect": int(res.get("indirectDependentCount") or 0),
            }
    return out


def flatten_graph(payload: dict) -> tuple[list[dict], list[tuple[int, int, str]]]:
    """deps.dev returns index-based edges; normalise to (from, to, requirement)."""
    nodes = []
    for n in payload.get("nodes") or []:
        vk = n.get("versionKey") or {}
        nodes.append({
            "ecosystem": (vk.get("system") or "").lower(),
            "name": vk.get("name"),
            "version": vk.get("version"),
            "relation": n.get("relation"),   # SELF | DIRECT | INDIRECT
            "errors": n.get("errors") or [],
        })
    edges = []
    for e in payload.get("edges") or []:
        try:
            edges.append((int(e.get("fromNode", 0)), int(e.get("toNode", 0)),
                          e.get("requirement") or ""))
        except (TypeError, ValueError):
            continue
    return nodes, edges
