"""
Structural metrics over the dependency graph.

Each metric is computed with NetworkX and shipped to the UI with a plain-English
description of what it means, because a number nobody can interpret is not
explainability.

An explicit non-claim, stated in the UI too: centrality is NOT exploitability.
A structurally central package is a package whose compromise would propagate
widely. Whether it *can* be compromised is a separate question, answered by the
trust channel (publishing surface) and the exploit channel (known CVEs).
"""
from __future__ import annotations

import math

import networkx as nx

from .builder import APP, MAINTAINER, PACKAGE

METRIC_DOCS = {
    "pagerank": (
        "PageRank on the dependency graph with edges reversed. High = a large "
        "share of the application's total dependency weight flows through this "
        "package."
    ),
    "betweenness": (
        "Fraction of shortest dependency paths that pass through this package. "
        "High = a chokepoint; removing it disconnects many paths."
    ),
    "in_app_dependents": (
        "How many packages inside this application depend on it, directly or "
        "transitively."
    ),
    "depth": (
        "Shortest number of dependency hops from the application to this "
        "package. Depth 1 = a direct dependency."
    ),
    "kcore": (
        "k-core number. High = sits inside a densely interconnected cluster of "
        "mutually depending packages."
    ),
    "ecosystem_dependents": (
        "Distinct packages in the public registry known to depend on this one "
        "(deps.dev). Indicative of relative popularity, not exact."
    ),
    "maintainer_fanout": (
        "The largest number of registry packages any single publisher of this "
        "package also controls. This is the blast radius of one phished account."
    ),
}


def package_nodes(g: nx.DiGraph) -> list[str]:
    return [n for n, d in g.nodes(data=True)
            if d.get("kind") == PACKAGE and not d.get("synthetic_fix_node")]


def dependency_subgraph(g: nx.DiGraph) -> nx.DiGraph:
    """Only app + package nodes joined by DEPENDS_ON. Metrics run on this."""
    keep = [n for n, d in g.nodes(data=True)
            if d.get("kind") in (APP, PACKAGE) and not d.get("synthetic_fix_node")]
    sub = g.subgraph(keep).copy()
    drop = [(u, v) for u, v, d in sub.edges(data=True)
            if d.get("kind") != "DEPENDS_ON"]
    sub.remove_edges_from(drop)
    return sub


def compute(g: nx.DiGraph) -> dict[str, dict]:
    """Returns {node_id: {metric: value}} for every package node."""
    sub = dependency_subgraph(g)
    pkgs = package_nodes(g)
    if not pkgs:
        return {}

    app = next((n for n, d in g.nodes(data=True) if d.get("kind") == APP), None)

    # PageRank on the reversed graph: importance flows from dependents to
    # dependencies, so a package many things depend on scores high.
    try:
        pr = nx.pagerank(sub.reverse(copy=True), alpha=0.85, max_iter=200)
    except Exception:
        pr = {n: 0.0 for n in sub}

    try:
        if sub.number_of_nodes() > 220:
            k = min(120, sub.number_of_nodes())
            bt = nx.betweenness_centrality(sub, k=k, normalized=True, seed=7)
        else:
            bt = nx.betweenness_centrality(sub, normalized=True)
    except Exception:
        bt = {n: 0.0 for n in sub}

    try:
        undirected = nx.Graph(sub)
        undirected.remove_edges_from(nx.selfloop_edges(undirected))
        core = nx.core_number(undirected)
    except Exception:
        core = {n: 0 for n in sub}

    depths: dict[str, int] = {}
    if app is not None and app in sub:
        try:
            depths = nx.single_source_shortest_path_length(sub, app)
        except Exception:
            depths = {}

    # Maintainer fan-out: worst-case packages controlled by any one publisher.
    fanout: dict[str, int] = {}
    for m, d in g.nodes(data=True):
        if d.get("kind") != MAINTAINER:
            continue
        controlled = d.get("packages_controlled")
        if not isinstance(controlled, int):
            continue
        for _, pkg in g.out_edges(m):
            fanout[pkg] = max(fanout.get(pkg, 0), controlled)

    out: dict[str, dict] = {}
    max_pr = max(pr.values()) if pr else 1.0
    for n in pkgs:
        try:
            dependents = len(nx.ancestors(sub, n)) if n in sub else 0
        except Exception:
            dependents = 0
        try:
            reach = len(nx.descendants(sub, n)) if n in sub else 0
        except Exception:
            reach = 0
        eco = g.nodes[n].get("depsdev_dependents") or {}
        out[n] = {
            "pagerank": round(pr.get(n, 0.0), 6),
            "pagerank_normalised": round(pr.get(n, 0.0) / max_pr, 4) if max_pr else 0.0,
            "betweenness": round(bt.get(n, 0.0), 6),
            "kcore": int(core.get(n, 0)),
            "depth": int(depths.get(n, 0)) if depths else None,
            "in_app_dependents": max(dependents - 1, 0),  # exclude the app node
            "in_app_reach": reach,
            "ecosystem_dependents": int(eco.get("total") or 0),
            "maintainer_fanout": int(fanout.get(n, 0)),
        }
    return out


def structural_score(metrics: dict) -> tuple[float, list[dict]]:
    """Collapse structural metrics into 0-100 with an itemised breakdown.

    Log-scaled because dependent counts are heavy-tailed: the difference between
    3 and 30 dependents matters far more than between 3,000 and 30,000.
    """
    pr = metrics.get("pagerank_normalised") or 0.0
    bt = min((metrics.get("betweenness") or 0.0) * 4.0, 1.0)
    in_app = math.log1p(metrics.get("in_app_dependents") or 0) / math.log1p(60)
    eco = math.log1p(metrics.get("ecosystem_dependents") or 0) / math.log1p(50_000)
    kcore = min((metrics.get("kcore") or 0) / 6.0, 1.0)

    parts = [
        ("PageRank share of dependency weight", 30.0 * min(pr, 1.0)),
        ("Betweenness (chokepoint position)", 22.0 * bt),
        ("Dependents inside this application", 22.0 * min(in_app, 1.0)),
        ("Dependents across the public registry", 18.0 * min(eco, 1.0)),
        ("k-core density", 8.0 * kcore),
    ]
    total = sum(v for _, v in parts)
    breakdown = [{"factor": k, "points": round(v, 1)} for k, v in parts]
    return round(min(total, 100.0), 1), breakdown


def maintainer_blast_radius(g: nx.DiGraph) -> list[dict]:
    """Rank publishing identities by what one compromised account would reach."""
    rows = []
    for m, d in g.nodes(data=True):
        if d.get("kind") != MAINTAINER:
            continue
        pkgs = [p for _, p in g.out_edges(m)]
        rows.append({
            "maintainer": d.get("name"),
            "packages_in_this_app": len(pkgs),
            "packages_in_registry": d.get("packages_controlled"),
            "packages": [g.nodes[p].get("name") for p in pkgs][:12],
        })
    rows.sort(
        key=lambda r: (r["packages_in_this_app"], r["packages_in_registry"] or 0),
        reverse=True,
    )
    return rows
