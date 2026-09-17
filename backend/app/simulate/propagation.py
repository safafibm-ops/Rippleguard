"""
COMPROMISE PROPAGATION SIMULATOR.

"Suppose package X were compromised right now." We then walk the graph in the
*dependent* direction (upward, toward the application) and outward into the
public ecosystem, decaying exposure along each edge.

THIS IS A SIMULATION. Nothing here asserts that any package is actually
compromised. Every number produced is an **Exposure Score**, never a
probability - the transmission weights are heuristics derived from observable
manifest facts, not from calibrated incident data.

Transmission model (Option C from the design: centrality-weighted propagation
with an inheritance term, chosen over probabilistic/GNN models because it is
defensible without training data).

    w(u -> v) = inheritance(v, u) * channel(u)

where
    inheritance(v, u)  how automatically v picks up a new publish of u
                       (the declared range between them, lockfile-discounted)
    channel(u)         1.0 if u executes an install hook, else 0.55
                       (without a hook, malicious code still runs on import,
                        but only if v actually loads that code path)

Node exposure = the maximum product of weights over any path from the
compromised node. Maximum, not sum: exposure is "can it get here", not "how
many ways".
"""
from __future__ import annotations

import heapq
import math

import networkx as nx

from ..graph.builder import APP, PACKAGE

NO_HOOK_CHANNEL = 0.55
HOOK_CHANNEL = 1.0


def _channel_factor(g: nx.DiGraph, node: str) -> float:
    if g.nodes[node].get("has_install_hook"):
        return HOOK_CHANNEL
    return NO_HOOK_CHANNEL


def transmission_weight(g: nx.DiGraph, source: str, dependent: str) -> float:
    """Weight of the edge dependent -> source, traversed backwards."""
    data = g.get_edge_data(dependent, source) or {}
    inheritance = data.get("floatiness")
    if inheritance is None:
        inheritance = 0.55
    return max(0.0, min(1.0, inheritance * _channel_factor(g, source)))


def simulate(
    g: nx.DiGraph,
    compromised: str,
    *,
    max_depth: int = 8,
    min_exposure: float = 0.01,
) -> dict:
    """Forward compromise simulation from `compromised`."""
    if compromised not in g:
        raise KeyError(f"unknown node: {compromised}")

    # Dijkstra over -log(weight) == maximising the product of weights.
    best: dict[str, float] = {compromised: 1.0}
    prev: dict[str, str] = {}
    depth: dict[str, int] = {compromised: 0}
    heap: list[tuple[float, str]] = [(0.0, compromised)]
    visited: set[str] = set()

    while heap:
        cost, node = heapq.heappop(heap)
        if node in visited:
            continue
        visited.add(node)
        if depth[node] >= max_depth:
            continue
        # Walk to things that depend on `node`.
        for dependent, _ in g.in_edges(node):
            edata = g.get_edge_data(dependent, node) or {}
            if edata.get("kind") != "DEPENDS_ON":
                continue
            w = transmission_weight(g, node, dependent)
            if w <= 0:
                continue
            new_exposure = best[node] * w
            if new_exposure < min_exposure:
                continue
            if new_exposure > best.get(dependent, 0.0):
                best[dependent] = new_exposure
                prev[dependent] = node
                depth[dependent] = depth[node] + 1
                heapq.heappush(heap, (-math.log(new_exposure), dependent))

    reached = {n: e for n, e in best.items() if n != compromised}
    pkg_reached = {n: e for n, e in reached.items()
                   if g.nodes[n].get("kind") == PACKAGE}
    app_reached = {n: e for n, e in reached.items()
                   if g.nodes[n].get("kind") == APP}

    def path_to(node: str) -> list[dict]:
        chain, cur = [], node
        while cur in prev:
            chain.append(cur)
            cur = prev[cur]
        chain.append(compromised)
        chain.reverse()
        steps = []
        for i, nid in enumerate(chain):
            nd = g.nodes[nid]
            step = {
                "id": nid,
                "label": (nd.get("name") or nid) +
                         (f"@{nd['version']}" if nd.get("version") else ""),
                "kind": nd.get("kind"),
            }
            if i > 0:
                ed = g.get_edge_data(chain[i], chain[i - 1]) or {}
                step["inherits_via"] = ed.get("spec", "?")
                step["edge_weight"] = round(
                    transmission_weight(g, chain[i - 1], chain[i]), 3
                )
            steps.append(step)
        return steps

    # Rank paths by terminal exposure; application-terminating paths win ties.
    candidates = sorted(
        reached.items(),
        key=lambda kv: (g.nodes[kv[0]].get("kind") == APP, kv[1]),
        reverse=True,
    )
    top_paths = []
    for node, exposure in candidates[:6]:
        top_paths.append({
            "target": node,
            "target_label": g.nodes[node].get("name", node),
            "target_kind": g.nodes[node].get("kind"),
            "exposure": round(exposure, 4),
            "hops": depth.get(node, 0),
            "steps": path_to(node),
            "why": _path_rationale(g, path_to(node), exposure),
        })

    # Blast radius, raw and weighted.
    raw = len(pkg_reached) + len(app_reached)
    weighted = sum(reached.values())
    total_pkgs = sum(1 for _, d in g.nodes(data=True) if d.get("kind") == PACKAGE)
    coverage = (len(pkg_reached) / total_pkgs) if total_pkgs else 0.0

    src = g.nodes[compromised]
    ecosystem_reach = src.get("depsdev_dependents") or {}
    downstream_sample = src.get("downstream_sample") or []

    blast = _blast_radius_score(
        coverage=coverage,
        weighted=weighted,
        app_hit=bool(app_reached),
        max_depth_reached=max(depth.values()) if depth else 0,
        ecosystem_dependents=int(ecosystem_reach.get("total") or 0),
    )

    return {
        "compromised": compromised,
        "compromised_label": f"{src.get('name')}@{src.get('version')}",
        "is_simulation": True,
        "disclaimer": (
            "Hypothetical scenario. This does not assert that "
            f"{src.get('name')} is compromised. All values are exposure scores, "
            "not probabilities."
        ),
        "reached_packages": len(pkg_reached),
        "reached_applications": len(app_reached),
        "application_exposure": round(max(app_reached.values()), 4) if app_reached else 0.0,
        "max_propagation_depth": max(depth.values()) if depth else 0,
        "in_app_coverage": round(coverage, 4),
        "weighted_reach": round(weighted, 3),
        "blast_radius": blast,
        "top_paths": top_paths,
        "reached": [
            {
                "id": n,
                "label": g.nodes[n].get("name", n),
                "version": g.nodes[n].get("version"),
                "kind": g.nodes[n].get("kind"),
                "exposure": round(e, 4),
                "hops": depth.get(n, 0),
            }
            for n, e in sorted(reached.items(), key=lambda kv: kv[1], reverse=True)
        ][:200],
        "ecosystem": {
            "registry_dependents": ecosystem_reach.get("total"),
            "direct_registry_dependents": ecosystem_reach.get("direct"),
            "sample_downstream_packages": downstream_sample[:15],
            "note": ("Registry-wide figures come from deps.dev/ecosyste.ms and "
                     "describe the public ecosystem, not this application. "
                     "deps.dev counts are indicative, not exact."),
        },
    }


def _path_rationale(g: nx.DiGraph, steps: list[dict], exposure: float) -> str:
    if len(steps) < 2:
        return "Direct exposure."
    weakest = min((s for s in steps[1:] if "edge_weight" in s),
                  key=lambda s: s["edge_weight"], default=None)
    head, tail = steps[0]["label"], steps[-1]["label"]
    base = (f"A malicious publish of {head} propagates through "
            f"{len(steps) - 2} intermediate package(s) to {tail} "
            f"at exposure {exposure:.2f}.")
    if weakest:
        base += (f" The narrowest link is \"{weakest['inherits_via']}\" "
                 f"(weight {weakest['edge_weight']}), which is where pinning "
                 f"would cut this path.")
    return base


def _blast_radius_score(
    *, coverage: float, weighted: float, app_hit: bool,
    max_depth_reached: int, ecosystem_dependents: int,
) -> dict:
    """0-100, itemised. Explicitly labelled as a modelled exposure figure."""
    parts = [
        ("Share of this application's packages reached", 34.0 * min(coverage, 1.0)),
        ("Exposure-weighted reach", 22.0 * min(weighted / 12.0, 1.0)),
        ("Reaches the application itself", 20.0 if app_hit else 0.0),
        ("Propagation depth", 10.0 * min(max_depth_reached / 5.0, 1.0)),
        ("Public registry dependents",
         14.0 * min(math.log1p(ecosystem_dependents) / math.log1p(50_000), 1.0)),
    ]
    total = round(sum(v for _, v in parts), 1)
    return {
        "score": min(total, 100.0),
        "breakdown": [{"factor": k, "points": round(v, 1)} for k, v in parts],
        "label": "modelled exposure, not a probability",
    }


def rank_by_blast_radius(g: nx.DiGraph, limit: int = 10) -> list[dict]:
    """Which single package, if compromised, would expose the most?

    This answers Core Feature 13 - risk concentration - by running the
    simulation for every package and ranking the results.
    """
    rows = []
    for n, d in g.nodes(data=True):
        if d.get("kind") != PACKAGE or d.get("synthetic_fix_node"):
            continue
        try:
            res = simulate(g, n, max_depth=6)
        except Exception:
            continue
        rows.append({
            "id": n,
            "name": d.get("name"),
            "version": d.get("version"),
            "blast_radius": res["blast_radius"]["score"],
            "reached_packages": res["reached_packages"],
            "reaches_application": res["reached_applications"] > 0,
            "has_install_hook": bool(d.get("has_install_hook")),
        })
    rows.sort(key=lambda r: r["blast_radius"], reverse=True)
    return rows[:limit]
