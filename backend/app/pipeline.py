"""
The scan pipeline.

    manifest/SBOM/repo
        -> Project (declared deps, ranges, lockfile state)
        -> dependency graph (deps.dev | npm registry | lockfile)
        -> registry metadata (install hooks, maintainers, publish dates)
        -> OSV advisories
        -> structural metrics
        -> import-graph reachability
        -> exploit channel + trust channel + structural
        -> blend, rank inversion, blast-radius ranking

`rescore(graph)` is deliberately a pure function of the graph so the
counterfactual engine can run the exact same scoring code on a mutated copy.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any, Callable

import networkx as nx

from .clients import github
from .clients.base import fetcher
from .clients import osv
from .config import settings
from .graph import builder, metrics as gmetrics
from .ingest.manifest import Project, build_project
from .reachability import imports as reach
from .scoring import combine, exploit as exploit_scoring, trust as trust_scoring

JOBS: dict[str, dict] = {}


def _new_job() -> str:
    jid = uuid.uuid4().hex[:12]
    JOBS[jid] = {
        "id": jid,
        "status": "queued",
        "created": time.time(),
        "stages": [],
        "result": None,
        "error": None,
    }
    return jid


def _stage(jid: str, name: str, detail: str = "", state: str = "done") -> None:
    job = JOBS.get(jid)
    if not job:
        return
    job["stages"].append({"name": name, "detail": detail, "state": state,
                          "at": round(time.time() - job["created"], 2)})


STAGE_ORDER = [
    "Read manifest", "Resolve dependency graph", "Registry metadata",
    "Vulnerability intelligence", "Ecosystem reach", "Graph metrics",
    "Reachability proxy", "Dual-channel scoring", "Blast-radius ranking",
]


# --------------------------------------------------------------------------
# Scoring, as a pure function of the graph
# --------------------------------------------------------------------------

def make_rescorer(project: Project, imported: set[str],
                  source_files: dict[str, str], osv_available: bool) -> Callable:
    """Build the rescore(graph) closure used by both the scan and the
    counterfactual engine."""

    def rescore(g: nx.DiGraph) -> dict:
        m = gmetrics.compute(g)
        app = next((n for n, d in g.nodes(data=True) if d.get("kind") == builder.APP),
                   None)
        findings = []
        for nid, node in g.nodes(data=True):
            if node.get("kind") != builder.PACKAGE or node.get("synthetic_fix_node"):
                continue
            nm = m.get(nid, {})
            edge = g.get_edge_data(app, nid) if app else None
            if edge is None:
                # Not a direct dependency: its inheritance exposure is the worst
                # of the ranges its parents declare on it. Using the max (rather
                # than a constant) means pinning a transitive edge is visible in
                # the score, which is what the counterfactual engine needs.
                incoming = [d for _u, _v, d in g.in_edges(nid, data=True)
                            if d.get("kind") == "DEPENDS_ON" and "floatiness" in d]
                if incoming:
                    edge = max(incoming, key=lambda d: d["floatiness"])
            if edge is None:
                # Not a direct dependency: its inheritance exposure is the worst
                # of the ranges its parents declare on it. Using the max (rather
                # than a constant) means pinning a transitive edge is visible in
                # the score, which is what the counterfactual engine needs.
                incoming = [d for _u, _v, d in g.in_edges(nid, data=True)
                            if d.get("kind") == "DEPENDS_ON" and "floatiness" in d]
                if incoming:
                    edge = max(incoming, key=lambda d: d["floatiness"])

            vulns = []
            for _u, v, d in g.out_edges(nid, data=True):
                if d.get("kind") == "AFFECTED_BY":
                    vd = g.nodes[v]
                    vulns.append({k: vd.get(k) for k in
                                  ("id", "cve", "summary", "cvss", "severity_label",
                                   "cvss_vector", "published", "fixed_version",
                                   "references")})
            vulns.sort(key=lambda v: v.get("cvss") or 0, reverse=True)

            r = reach.classify(node["name"], imported, source_files,
                               [v.get("summary") or "" for v in vulns])
            ex = exploit_scoring.score_package(nid, node, vulns, r, nm)
            tr = trust_scoring.score_package(nid, node, edge, nm,
                                             ignore_scripts=project.ignore_scripts)
            st, st_breakdown = gmetrics.structural_score(nm)
            total, breakdown, note = combine.blend(ex["score"], tr["score"], st,
                                                   osv_available)
            findings.append({
                "id": nid,
                "name": node["name"],
                "version": node["version"],
                "ecosystem": node.get("ecosystem"),
                "direct": bool(node.get("direct")),
                "scope": node.get("scope", "runtime"),
                "rippleguard_score": total,
                "score_breakdown": breakdown,
                "score_note": note,
                "exploit_score": ex["score"],
                "trust_score": tr["score"],
                "structural_score": st,
                "structural_breakdown": st_breakdown,
                "exploit": ex,
                "trust": tr,
                "metrics": nm,
                "reachability": r,
            })

        findings.sort(key=lambda f: f["rippleguard_score"], reverse=True)
        portfolio = round(
            sum(f["rippleguard_score"] for f in findings[:10]) / max(1, min(10, len(findings))),
            1,
        ) if findings else 0.0
        return {"findings": findings, "portfolio_score": portfolio}

    return rescore


# --------------------------------------------------------------------------
# Full scan
# --------------------------------------------------------------------------

async def load_from_github(repo_url: str) -> tuple[dict, dict]:
    """Returns (manifest_files, source_files)."""
    parsed = github.parse_repo_url(repo_url)
    if not parsed:
        raise ValueError(
            "Could not parse that as a GitHub repository URL. "
            "Expected https://github.com/owner/repo"
        )
    owner, repo = parsed
    meta = await github.repo_meta(owner, repo)
    ref = (meta or {}).get("default_branch", "HEAD")

    manifests: dict[str, str] = {}
    results = await asyncio.gather(
        *(github.get_file(owner, repo, f, ref) for f in github.MANIFEST_FILES),
        return_exceptions=True,
    )
    for name, text in zip(github.MANIFEST_FILES, results):
        if isinstance(text, str) and text.strip():
            manifests[name] = text

    tree = await github.list_tree(owner, repo, ref)
    candidates = [p for p in tree if reach.is_first_party(p)][:40]
    src_results = await asyncio.gather(
        *(github.get_file(owner, repo, p, ref) for p in candidates),
        return_exceptions=True,
    )
    sources = {p: t for p, t in zip(candidates, src_results) if isinstance(t, str)}

    if not manifests:
        raise ValueError(
            f"No supported manifest found in {owner}/{repo}. "
            "RippleGuard looks for package.json, requirements.txt, pom.xml, "
            "go.mod or a lockfile at the repository root."
        )
    return manifests, sources


async def run_scan(jid: str, *, repo_url: str = "", files: dict[str, str] | None = None,
                   source_files: dict[str, str] | None = None) -> None:
    job = JOBS[jid]
    job["status"] = "running"
    fetcher.reset_health()
    try:
        manifests = files or {}
        sources = source_files or {}

        if repo_url:
            _stage(jid, "Read manifest", f"fetching {repo_url}", "running")
            manifests, sources = await load_from_github(repo_url)
            job["stages"].pop()
        _stage(jid, "Read manifest",
               f"{len(manifests)} manifest file(s), {len(sources)} source file(s)")

        project = build_project(manifests, settings.include_dev_dependencies)
        project.source_files = sources

        _stage(jid, "Resolve dependency graph", "resolving transitive tree", "running")
        g, report = await builder.build_dependency_graph(project)
        job["stages"].pop()
        _stage(jid, "Resolve dependency graph",
               f"{report.packages_resolved} packages via "
               f"{', '.join(report.resolver_used) or 'no resolver'}")

        _stage(jid, "Registry metadata", "install hooks + publishers", "running")
        reg = await builder.attach_registry_metadata(g)
        job["stages"].pop()
        _stage(jid, "Registry metadata",
               f"{reg['packages_with_registry_metadata']} packages, "
               f"{reg['maintainer_nodes']} publishing identities")

        pkgs = [(d["ecosystem"], d["name"], d["version"])
                for _n, d in g.nodes(data=True)
                if d.get("kind") == builder.PACKAGE and not d.get("synthetic_fix_node")]
        _stage(jid, "Vulnerability intelligence", "querying OSV", "running")
        advisories = await osv.enrich(pkgs)
        job["stages"].pop()
        osv_health = fetcher.health.get("osv")
        osv_available = bool(osv_health and osv_health.reachable)
        vuln_links = builder.attach_vulnerabilities(g, advisories)
        _stage(jid, "Vulnerability intelligence",
               f"{vuln_links} advisory link(s) across {len(advisories)} package(s)"
               if osv_available else "OSV unreachable - exploit channel unavailable",
               "done" if osv_available else "degraded")

        _stage(jid, "Ecosystem reach", "downstream dependents", "running")
        eco = await builder.attach_ecosystem_reach(g)
        job["stages"].pop()
        _stage(jid, "Ecosystem reach",
               f"{eco['depsdev_dependent_counts']} dependent counts, "
               f"{eco['ecosystems_profiles']} registry profiles")

        _stage(jid, "Reachability proxy", "scanning first-party imports", "running")
        imported = reach.extract_imports(sources)
        job["stages"].pop()
        _stage(jid, "Reachability proxy",
               f"{len(imported)} package(s) imported by first-party code"
               if sources else "no first-party source available (upload a repo URL)")

        _stage(jid, "Graph metrics", "pagerank / betweenness / k-core", "running")
        rescore = make_rescorer(project, imported, sources, osv_available)
        scored = await asyncio.to_thread(rescore, g)
        job["stages"].pop()
        _stage(jid, "Graph metrics", f"{len(scored['findings'])} packages scored")

        _stage(jid, "Dual-channel scoring", "exploit vs trust", "running")
        inversion = combine.rank_inversion(scored["findings"])
        job["stages"].pop()
        _stage(jid, "Dual-channel scoring",
               f"largest rank move: "
               f"{inversion['largest_upward_moves'][0]['movement'] if inversion['largest_upward_moves'] else 0} places")

        _stage(jid, "Blast-radius ranking", "simulating every package", "running")
        from .simulate.propagation import rank_by_blast_radius
        blast = await asyncio.to_thread(rank_by_blast_radius, g, 10)
        job["stages"].pop()
        _stage(jid, "Blast-radius ranking", f"top hub: {blast[0]['name']}" if blast else "n/a")

        job["graph"] = g
        job["project"] = project
        job["rescore"] = rescore
        job["result"] = {
            "scan_id": jid,
            "project": project.as_dict(),
            "summary": _summary(scored, g, blast, inversion),
            "findings": scored["findings"],
            "portfolio_score": scored["portfolio_score"],
            "rank_inversion": inversion,
            "blast_ranking": blast,
            "maintainer_risk": gmetrics.maintainer_blast_radius(g)[:10],
            "build_report": report.as_dict(),
            "registry_report": reg,
            "ecosystem_report": eco,
            "sources": fetcher.health_report(),
            "metric_docs": gmetrics.METRIC_DOCS,
            "reachability_disclaimer": reach.DISCLAIMER,
            "osv_available": osv_available,
            "duration_seconds": round(time.time() - job["created"], 2),
        }
        job["status"] = "complete"
    except Exception as exc:  # surfaced verbatim in the UI
        job["status"] = "error"
        job["error"] = f"{type(exc).__name__}: {exc}"
        _stage(jid, "Failed", job["error"], "error")


def _summary(scored: dict, g: nx.DiGraph, blast: list[dict], inversion: dict) -> dict:
    findings = scored["findings"]
    vulnerable = [f for f in findings if f["exploit"].get("vulnerabilities")]
    hooked = [f for f in findings if f["trust"].get("has_install_hook")]
    floaty = [f for f in findings
              if f["trust"].get("range_kind") in ("caret", "range_op", "wildcard")]
    direct = [f for f in findings if f["direct"]]
    return {
        "packages": len(findings),
        "direct_dependencies": len(direct),
        "vulnerable_packages": len(vulnerable),
        "advisories": sum(len(f["exploit"]["vulnerabilities"]) for f in findings),
        "packages_with_install_hooks": len(hooked),
        "packages_on_floating_ranges": len(floaty),
        "publishing_identities": sum(1 for _n, d in g.nodes(data=True)
                                     if d.get("kind") == builder.MAINTAINER),
        "portfolio_score": scored["portfolio_score"],
        "top_blast_radius": blast[0] if blast else None,
        "headline_inversion": inversion.get("headline_inversion"),
        "max_depth": max((f["metrics"].get("depth") or 0 for f in findings), default=0),
    }


def graph_payload(g: nx.DiGraph, findings: list[dict], limit: int = 260) -> dict:
    """Trimmed graph for the browser renderer."""
    score_of = {f["id"]: f for f in findings}
    keep = set()
    for n, d in g.nodes(data=True):
        if d.get("kind") == builder.APP:
            keep.add(n)
        elif d.get("kind") == builder.PACKAGE and not d.get("synthetic_fix_node"):
            keep.add(n)
    if len(keep) > limit:
        ranked = sorted(
            (n for n in keep if g.nodes[n].get("kind") == builder.PACKAGE),
            key=lambda n: score_of.get(n, {}).get("rippleguard_score", 0),
            reverse=True,
        )[:limit]
        keep = set(ranked) | {n for n in keep
                              if g.nodes[n].get("kind") == builder.APP}

    nodes = []
    for n in keep:
        d = g.nodes[n]
        f = score_of.get(n, {})
        nodes.append({
            "id": n,
            "kind": d.get("kind"),
            "label": d.get("name"),
            "version": d.get("version"),
            "direct": bool(d.get("direct")),
            "scope": d.get("scope", "runtime"),
            "score": f.get("rippleguard_score", 0.0),
            "exploit": f.get("exploit_score", 0.0),
            "trust": f.get("trust_score", 0.0),
            "vulns": len(f.get("exploit", {}).get("vulnerabilities") or []),
            "hook": bool(d.get("has_install_hook")),
            "range_kind": f.get("trust", {}).get("range_kind"),
            "depth": (f.get("metrics") or {}).get("depth"),
        })
    edges = [
        {"source": u, "target": v, "spec": d.get("spec", ""),
         "floatiness": d.get("floatiness", 0.0), "scope": d.get("scope", "runtime")}
        for u, v, d in g.edges(data=True)
        if d.get("kind") == "DEPENDS_ON" and u in keep and v in keep
    ]
    return {"nodes": nodes, "edges": edges,
            "truncated": len(keep) < sum(1 for _ in g.nodes)}
