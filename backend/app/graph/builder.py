"""
Builds the RippleGuard multi-layer graph.

Node types
    app         the analysed application (exactly one)
    package     a resolved package@version
    maintainer  a publishing identity that can push new versions of a package
    vuln        an OSV advisory

Edge types
    DEPENDS_ON   app|package -> package   (carries the declared range)
    PUBLISHES    maintainer  -> package   (the trust channel's attack edge)
    AFFECTED_BY  package     -> vuln
    FIXED_BY     vuln        -> package@fixed_version (informational)

The maintainer layer is the part no free tool draws. It is what turns
"one phished npm account" into a visible, countable blast radius.

Resolution strategy, in order, so the tool degrades instead of failing:
    1. deps.dev GetDependencies - authoritative resolved graph, multi-ecosystem
    2. npm registry BFS with our own semver resolver (npm only)
    3. lockfile contents alone (flat, no edges between transitive packages)
"""
from __future__ import annotations

import asyncio
from typing import Any

import networkx as nx

from ..clients import depsdev, ecosystems, npm_registry
from ..config import settings
from ..ingest.manifest import Project
from ..ingest.ranges import floatiness

# Bounds on the publisher fan-out lookup. The npm search endpoint rate-limits
# aggressively, and fan-out only changes the ranking for well-connected
# packages, so we spend the budget where it can move a score.
MAINTAINER_LOOKUP_PACKAGES = 45
MAINTAINER_LOOKUP_BUDGET = 60

APP = "app"
PACKAGE = "package"
MAINTAINER = "maintainer"
VULN = "vuln"


def pid(ecosystem: str, name: str, version: str) -> str:
    return f"{ecosystem}:{name}@{version}"


class BuildReport:
    """What the resolver actually managed to do - surfaced verbatim in the UI."""

    def __init__(self) -> None:
        self.resolver_used: list[str] = []
        self.degraded: list[str] = []
        self.packages_resolved = 0
        self.truncated = False

    def as_dict(self) -> dict:
        return {
            "resolvers_used": self.resolver_used,
            "degraded": self.degraded,
            "packages_resolved": self.packages_resolved,
            "truncated_at_limit": self.truncated,
        }


async def _resolve_via_depsdev(
    project: Project, g: nx.DiGraph, report: BuildReport
) -> bool:
    """Ask deps.dev for a resolved graph per direct dependency, then merge."""
    direct = [d for d in project.declared]
    if not direct:
        return False

    async def one(dep) -> tuple[Any, Any]:
        version = dep.locked_version
        if not version and dep.ecosystem == "npm":
            version = await npm_registry.resolve_version(dep.name, dep.spec)
        if not version:
            return dep, None
        payload = await depsdev.resolved_dependencies(
            dep.ecosystem, dep.name, version
        )
        return dep, payload

    results = await asyncio.gather(*(one(d) for d in direct), return_exceptions=True)
    merged = 0
    for res in results:
        if isinstance(res, Exception) or not isinstance(res, tuple):
            continue
        dep, payload = res
        if not isinstance(payload, dict):
            continue
        nodes, edges = depsdev.flatten_graph(payload)
        if not nodes:
            continue
        merged += 1
        ids: list[str | None] = []
        for n in nodes:
            if not n["name"] or not n["version"]:
                ids.append(None)
                continue
            nid = pid(n["ecosystem"] or dep.ecosystem, n["name"], n["version"])
            if nid not in g:
                g.add_node(nid, kind=PACKAGE, ecosystem=n["ecosystem"] or dep.ecosystem,
                           name=n["name"], version=n["version"], direct=False,
                           scope="runtime")
            ids.append(nid)
        # node 0 is SELF - the direct dependency itself
        if ids and ids[0]:
            g.nodes[ids[0]]["direct"] = True
            g.nodes[ids[0]]["scope"] = dep.scope
        for a, b, requirement in edges:
            if a < len(ids) and b < len(ids) and ids[a] and ids[b]:
                g.add_edge(ids[a], ids[b], kind="DEPENDS_ON",
                           spec=requirement or "*", scope="runtime")
    if merged:
        report.resolver_used.append(f"deps.dev GetDependencies ({merged} subtrees)")
    return merged > 0


async def _resolve_via_npm(
    project: Project, g: nx.DiGraph, report: BuildReport
) -> bool:
    """Breadth-first resolution straight off the npm registry."""
    npm_deps = [d for d in project.declared if d.ecosystem == "npm"]
    if not npm_deps:
        return False

    frontier: list[tuple[str, str, str, int, str]] = []  # name, spec, parent, depth, scope
    for dep in npm_deps:
        frontier.append((dep.name, dep.spec, "", 0, dep.scope))

    seen: dict[str, str] = {}
    added = 0
    depth = 0
    while frontier and added < settings.max_packages and depth <= settings.max_depth:
        batch, frontier = frontier, []
        depth += 1

        async def resolve(item):
            name, spec, parent, d, scope = item
            version = await npm_registry.resolve_version(name, spec)
            if not version:
                return None
            meta = await npm_registry.version_metadata(name, version)
            return name, spec, parent, d, scope, version, meta

        results = await asyncio.gather(*(resolve(i) for i in batch),
                                       return_exceptions=True)
        for res in results:
            if not isinstance(res, tuple):
                continue
            name, spec, parent, d, scope, version, meta = res
            nid = pid("npm", name, version)
            if nid not in g:
                if added >= settings.max_packages:
                    report.truncated = True
                    continue
                g.add_node(nid, kind=PACKAGE, ecosystem="npm", name=name,
                           version=version, direct=(d == 0), scope=scope)
                added += 1
                seen[name] = version
                for child, cspec in (meta.get("dependencies") or {}).items():
                    frontier.append((child, str(cspec), nid, d + 1, "runtime"))
            if parent and parent in g:
                g.add_edge(parent, nid, kind="DEPENDS_ON", spec=spec, scope=scope)
    if added:
        report.resolver_used.append(f"npm registry BFS ({added} packages)")
    return added > 0


def _resolve_via_lockfile(project: Project, g: nx.DiGraph, report: BuildReport) -> bool:
    added = 0
    for dep in project.declared:
        version = dep.locked_version or (dep.spec if dep.spec[:1].isdigit() else None)
        if not version:
            continue
        nid = pid(dep.ecosystem, dep.name, version)
        if nid not in g:
            g.add_node(nid, kind=PACKAGE, ecosystem=dep.ecosystem, name=dep.name,
                       version=version, direct=True, scope=dep.scope)
            added += 1
    if added:
        report.resolver_used.append(f"lockfile/SBOM versions only ({added} packages)")
        report.degraded.append(
            "Transitive edges unavailable: no resolver reachable, so the graph is "
            "flat and downstream reach is understated."
        )
    return added > 0


async def build_dependency_graph(project: Project) -> tuple[nx.DiGraph, BuildReport]:
    g = nx.DiGraph()
    report = BuildReport()

    app_id = f"app:{project.name}@{project.version}"
    g.add_node(app_id, kind=APP, name=project.name, version=project.version,
               ecosystem="application")

    ok = await _resolve_via_depsdev(project, g, report)
    if not ok:
        report.degraded.append("deps.dev unreachable; fell back to npm registry.")
        ok = await _resolve_via_npm(project, g, report)
    if not ok:
        report.degraded.append("npm registry unreachable; using lockfile versions only.")
        _resolve_via_lockfile(project, g, report)

    # Wire the app to its declared direct dependencies, carrying the range.
    for dep in project.declared:
        match = None
        for nid, data in g.nodes(data=True):
            if data.get("kind") == PACKAGE and data.get("name") == dep.name \
                    and data.get("ecosystem") == dep.ecosystem:
                match = nid
                break
        if match is None:
            continue
        pinned = bool(dep.locked_version and dep.lock_integrity)
        factor, kind, reason = floatiness(
            dep.spec, ecosystem=dep.ecosystem, lockfile_pinned=pinned
        )
        g.add_edge(app_id, match, kind="DEPENDS_ON", spec=dep.spec, scope=dep.scope,
                   declared=True, floatiness=factor, range_kind=kind,
                   floatiness_reason=reason)
        g.nodes[match]["direct"] = True
        g.nodes[match]["declared_spec"] = dep.spec
        g.nodes[match]["scope"] = dep.scope
        g.nodes[match]["lock_integrity"] = pinned

    # Transitive edges get a floatiness value too (their parent's declared range).
    for u, v, data in g.edges(data=True):
        if data.get("kind") != "DEPENDS_ON" or "floatiness" in data:
            continue
        f, kind, reason = floatiness(data.get("spec"), ecosystem="npm",
                                     lockfile_pinned=project.has_lockfile)
        data["floatiness"] = f
        data["range_kind"] = kind
        data["floatiness_reason"] = reason

    report.packages_resolved = sum(
        1 for _, d in g.nodes(data=True) if d.get("kind") == PACKAGE
    )
    return g, report


async def attach_registry_metadata(g: nx.DiGraph) -> dict:
    """Install hooks, maintainers, publish dates - the trust-channel inputs.

    Adds MAINTAINER nodes and PUBLISHES edges. Only npm exposes maintainers
    cheaply; for other ecosystems we record that the layer is unavailable.
    """
    pkgs = [(n, d) for n, d in g.nodes(data=True) if d.get("kind") == PACKAGE]
    npm_pkgs = [(n, d) for n, d in pkgs if d.get("ecosystem") == "npm"]

    async def one(nid, data):
        meta = await npm_registry.version_metadata(data["name"], data["version"])
        return nid, meta

    results = await asyncio.gather(*(one(n, d) for n, d in npm_pkgs),
                                   return_exceptions=True)
    all_maintainers: list[str] = []
    resolved = 0
    for res in results:
        if not isinstance(res, tuple):
            continue
        nid, meta = res
        if not meta.get("available"):
            continue
        resolved += 1
        g.nodes[nid].update({
            "has_install_hook": meta["has_install_hook"],
            "install_scripts": meta["install_scripts"],
            "published_at": meta["published_at"],
            "deprecated": meta["deprecated"],
            "maintainers": meta["maintainers"],
            "latest_version": meta["latest_version"],
        })
        all_maintainers.extend(meta["maintainers"])

    # npm's search endpoint rate-limits hard (HTTP 429) and we only need
    # publisher fan-out for packages that can plausibly top the ranking, so we
    # bound the lookup to publishers of the most-depended-on packages.
    ranked_pkgs = sorted(npm_pkgs, key=lambda kv: g.in_degree(kv[0]), reverse=True)
    priority: list[str] = []
    for nid, _d in ranked_pkgs[:MAINTAINER_LOOKUP_PACKAGES]:
        priority.extend(g.nodes[nid].get("maintainers", []) or [])
    seen_users: list[str] = []
    for user in priority:
        if user not in seen_users:
            seen_users.append(user)
        if len(seen_users) >= MAINTAINER_LOOKUP_BUDGET:
            break
    counts = await npm_registry.bulk_maintainer_counts(seen_users)
    for nid, data in npm_pkgs:
        for user in g.nodes[nid].get("maintainers", []) or []:
            mid = f"maintainer:{user}"
            if mid not in g:
                g.add_node(mid, kind=MAINTAINER, name=user,
                           packages_controlled=counts.get(user))
            g.add_edge(mid, nid, kind="PUBLISHES")

    for nid, data in pkgs:
        if data.get("ecosystem") != "npm":
            g.nodes[nid].setdefault("has_install_hook", None)
            g.nodes[nid].setdefault("maintainers", [])

    return {
        "packages_with_registry_metadata": resolved,
        "maintainer_nodes": sum(1 for _, d in g.nodes(data=True)
                                if d.get("kind") == MAINTAINER),
        "maintainer_fanout_resolved": len(counts),
        "maintainer_fanout_budget": MAINTAINER_LOOKUP_BUDGET,
        "maintainer_fanout_note": (
            "Publisher fan-out is looked up for the most-depended-on packages "
            "only; npm's search endpoint rate-limits. Packages without a "
            "resolved fan-out score 0 on that factor, which understates them."
        ),
        "non_npm_packages_without_maintainer_layer":
            len(pkgs) - len(npm_pkgs),
    }


def attach_vulnerabilities(g: nx.DiGraph, advisories: dict[str, list[dict]]) -> int:
    """advisories keyed by 'name@version' from the OSV client."""
    count = 0
    for nid, data in list(g.nodes(data=True)):
        if data.get("kind") != PACKAGE:
            continue
        key = f"{data['name']}@{data['version']}"
        for rec in advisories.get(key, []):
            vid = f"vuln:{rec['id']}"
            if vid not in g:
                g.add_node(vid, kind=VULN, **{k: rec[k] for k in
                           ("id", "cve", "summary", "cvss", "severity_label",
                            "cvss_vector", "published", "fixed_version",
                            "references", "aliases")})
            g.add_edge(nid, vid, kind="AFFECTED_BY")
            if rec.get("fixed_version"):
                fixed_id = pid(data["ecosystem"], data["name"], rec["fixed_version"])
                g.add_edge(vid, fixed_id, kind="FIXED_BY")
                if fixed_id not in g:
                    g.add_node(fixed_id, kind=PACKAGE, ecosystem=data["ecosystem"],
                               name=data["name"], version=rec["fixed_version"],
                               synthetic_fix_node=True, direct=False)
            count += 1
    return count


async def attach_ecosystem_reach(g: nx.DiGraph, top_n: int = 25) -> dict:
    """Downstream reach *outside* the scanned app: dependent counts and lists.

    deps.dev gives counts, ecosyste.ms gives the actual dependent package list.
    We only fetch for the top-N packages by in-app importance to stay fast.
    """
    pkgs = [(n, d) for n, d in g.nodes(data=True)
            if d.get("kind") == PACKAGE and not d.get("synthetic_fix_node")]
    ranked = sorted(pkgs, key=lambda kv: g.in_degree(kv[0]), reverse=True)[:top_n]
    triples = [(d["ecosystem"], d["name"], d["version"]) for _, d in ranked]

    counts = await depsdev.bulk_dependent_counts(triples)

    async def eco_one(nid, data):
        info = await ecosystems.package_info(data["ecosystem"], data["name"])
        deps = await ecosystems.dependent_packages(data["ecosystem"], data["name"], 25)
        return nid, ecosystems.reach_signals(info), deps

    eco_results = await asyncio.gather(*(eco_one(n, d) for n, d in ranked),
                                       return_exceptions=True)
    eco_ok = 0
    for res in eco_results:
        if not isinstance(res, tuple):
            continue
        nid, signals, deps = res
        if signals.get("available"):
            eco_ok += 1
            g.nodes[nid]["ecosystem_reach"] = signals
            g.nodes[nid]["downstream_sample"] = deps

    for nid, data in ranked:
        key = f"{data['name']}@{data['version']}"
        if key in counts:
            g.nodes[nid]["depsdev_dependents"] = counts[key]

    return {
        "queried": len(ranked),
        "depsdev_dependent_counts": len(counts),
        "ecosystems_profiles": eco_ok,
        "note": ("deps.dev dependent counts are indicative of relative popularity, "
                 "not exact. ecosyste.ms dependent lists are registry-declared, "
                 "not install-resolved."),
    }
