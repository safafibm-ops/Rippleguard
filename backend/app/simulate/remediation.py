"""
COUNTERFACTUAL REMEDIATION.

"What if we fix this?" - modelled by actually mutating a copy of the graph,
re-running the full scoring pipeline on it, and diffing the result. Nothing is
estimated with a fudge factor; every "after" number is produced by the same
code path that produced the "before" number.

Five actions, chosen because they map to what a developer can actually do on
a Tuesday afternoon:

    pin              change "^1.2.3" to "1.2.3" and commit the lockfile
    ignore_scripts   set ignore-scripts=true in .npmrc (kills the install-hook path)
    upgrade          move to the OSV-reported fixed version
    isolate          vendor / sandbox so transmission is capped
    remove           drop the dependency entirely

The important output is not a single winner: it is that different actions fix
different channels. Pinning collapses trust-channel exposure and does nothing
for a CVE. Upgrading clears the CVE and leaves the publishing path wide open.
Showing that trade-off side by side is the point.
"""
from __future__ import annotations

import copy

import networkx as nx

from ..graph.builder import APP, PACKAGE
from .propagation import simulate

ACTIONS = ["pin", "ignore_scripts", "upgrade", "isolate", "remove"]

ACTION_DESCRIPTION = {
    "pin": "Pin to an exact version and commit the lockfile",
    "ignore_scripts": "Disable install scripts (.npmrc ignore-scripts=true)",
    "upgrade": "Upgrade to the version OSV reports as fixed",
    "isolate": "Vendor or sandbox the dependency",
    "remove": "Remove the dependency",
}

# Effort is a coarse, transparent 1-5 scale. We do NOT claim a monetary cost -
# we have no real cost data, and inventing one would be exactly the kind of
# unfounded number this project is arguing against.
ACTION_EFFORT = {
    "pin": 1,
    "ignore_scripts": 2,
    "upgrade": 3,
    "isolate": 4,
    "remove": 5,
}

EFFORT_NOTE = (
    "Effort is a 1-5 ordinal heuristic, not a cost estimate. We have no real "
    "engineering-cost data and do not fabricate one."
)


def _clone(g: nx.DiGraph) -> nx.DiGraph:
    return copy.deepcopy(g)


def apply_action(g: nx.DiGraph, target: str, action: str) -> tuple[nx.DiGraph, list[str]]:
    """Return a mutated copy of the graph plus a log of what changed."""
    h = _clone(g)
    log: list[str] = []
    if target not in h:
        raise KeyError(target)
    node = h.nodes[target]

    if action == "pin":
        for u, _v, data in list(h.in_edges(target, data=True)):
            if data.get("kind") != "DEPENDS_ON":
                continue
            old = data.get("spec", "?")
            data["spec"] = node.get("version", old)
            data["floatiness"] = 0.02
            data["range_kind"] = "exact"
            data["floatiness_reason"] = "pinned by remediation simulation"
            log.append(f'{h.nodes[u].get("name", u)}: "{old}" -> '
                       f'"{node.get("version")}" (exact)')

    elif action == "ignore_scripts":
        changed = 0
        for n, d in h.nodes(data=True):
            if d.get("kind") == PACKAGE and d.get("has_install_hook"):
                d["has_install_hook"] = False
                d["install_scripts_suppressed"] = True
                changed += 1
        log.append(f"install scripts disabled for {changed} package(s) "
                   f"across the whole tree")

    elif action == "upgrade":
        fixed = None
        for _u, v, data in h.out_edges(target, data=True):
            if data.get("kind") == "AFFECTED_BY":
                fixed = fixed or h.nodes[v].get("fixed_version")
        if not fixed:
            log.append("no fixed version published in OSV for this package - "
                       "upgrade cannot be modelled")
        else:
            drop = [(u, v) for u, v, d in h.out_edges(target, data=True)
                    if d.get("kind") == "AFFECTED_BY"]
            h.remove_edges_from(drop)
            old = node.get("version")
            node["version"] = fixed
            node["upgraded_from"] = old
            node["published_at"] = None  # a fresh release resets the detection window
            log.append(f'{node.get("name")}: {old} -> {fixed} '
                       f'({len(drop)} advisory link(s) cleared)')

    elif action == "isolate":
        for _u, _v, data in list(h.in_edges(target, data=True)):
            if data.get("kind") == "DEPENDS_ON":
                data["floatiness"] = min(data.get("floatiness", 0.5), 0.15)
                data["floatiness_reason"] = "vendored/sandboxed by remediation simulation"
        node["has_install_hook"] = False
        node["isolated"] = True
        log.append("transmission capped at 0.15 and install hooks neutralised")

    elif action == "remove":
        exclusive = _exclusively_owned(h, target)
        h.remove_nodes_from(exclusive | {target})
        log.append(f"removed {target} and {len(exclusive)} package(s) that "
                   f"nothing else depended on")
    else:
        raise ValueError(f"unknown action: {action}")

    return h, log


def _exclusively_owned(g: nx.DiGraph, target: str) -> set[str]:
    """Transitive deps that only exist because of `target`."""
    owned: set[str] = set()
    frontier = [v for _u, v, d in g.out_edges(target, data=True)
                if d.get("kind") == "DEPENDS_ON"]
    while frontier:
        node = frontier.pop()
        if node in owned or node == target:
            continue
        parents = [u for u, _v, d in g.in_edges(node, data=True)
                   if d.get("kind") == "DEPENDS_ON"]
        if all(p == target or p in owned for p in parents):
            owned.add(node)
            frontier.extend(v for _u, v, d in g.out_edges(node, data=True)
                            if d.get("kind") == "DEPENDS_ON")
    return owned


def evaluate(
    g: nx.DiGraph,
    target: str,
    rescore,
    actions: list[str] | None = None,
) -> dict:
    """Run every action and diff the results.

    `rescore(graph) -> dict` is injected so this module stays decoupled from the
    scoring pipeline; the API passes the real pipeline function, which means the
    "after" numbers are produced by exactly the same code as the "before".
    """
    baseline = rescore(g)
    try:
        base_sim = simulate(g, target, max_depth=6)
        base_blast = base_sim["blast_radius"]["score"]
    except Exception:
        base_blast = 0.0

    base_finding = _finding(baseline, target)
    results = []
    for action in (actions or ACTIONS):
        try:
            mutated, log = apply_action(g, target, action)
        except Exception as exc:
            results.append({"action": action, "error": str(exc)})
            continue

        after = rescore(mutated)
        still_there = target in mutated
        after_finding = _finding(after, target) if still_there else None
        try:
            after_blast = (simulate(mutated, target, max_depth=6)["blast_radius"]["score"]
                           if still_there else 0.0)
        except Exception:
            after_blast = 0.0

        results.append({
            "action": action,
            "description": ACTION_DESCRIPTION[action],
            "effort": ACTION_EFFORT[action],
            "changes": log,
            "before": {
                "rippleguard": base_finding.get("rippleguard_score", 0.0),
                "exploit": base_finding.get("exploit_score", 0.0),
                "trust": base_finding.get("trust_score", 0.0),
                "blast_radius": base_blast,
            },
            "after": {
                "rippleguard": (after_finding or {}).get("rippleguard_score", 0.0),
                "exploit": (after_finding or {}).get("exploit_score", 0.0),
                "trust": (after_finding or {}).get("trust_score", 0.0),
                "blast_radius": after_blast,
            },
            "portfolio_before": baseline.get("portfolio_score", 0.0),
            "portfolio_after": after.get("portfolio_score", 0.0),
            "package_removed": not still_there,
        })

    for r in results:
        if "error" in r:
            continue
        r["risk_reduction"] = round(r["before"]["rippleguard"] - r["after"]["rippleguard"], 1)
        r["blast_reduction"] = round(r["before"]["blast_radius"] - r["after"]["blast_radius"], 1)
        r["exploit_reduction"] = round(r["before"]["exploit"] - r["after"]["exploit"], 1)
        r["trust_reduction"] = round(r["before"]["trust"] - r["after"]["trust"], 1)
        r["reduction_per_effort"] = round(r["risk_reduction"] / r["effort"], 2)
        r["fixes_channel"] = _channel_verdict(r)

    ranked = sorted(
        [r for r in results if "error" not in r],
        key=lambda r: (r["reduction_per_effort"], r["risk_reduction"]),
        reverse=True,
    )
    return {
        "target": target,
        "options": results,
        "recommended": ranked[0]["action"] if ranked else None,
        "ranking_rule": "risk reduction divided by ordinal effort (1-5)",
        "effort_note": EFFORT_NOTE,
        "channel_insight": _cross_channel_insight(results),
    }


def _channel_verdict(r: dict) -> str:
    e, t = r["exploit_reduction"], r["trust_reduction"]
    if r["package_removed"]:
        return "both channels (package gone)"
    if e > 2 and t > 2:
        return "both channels"
    if t > 2:
        return "trust channel only"
    if e > 2:
        return "exploit channel only"
    return "neither channel materially"


def _cross_channel_insight(results: list[dict]) -> str:
    live = [r for r in results if "error" not in r]
    if not live:
        return ""
    trust_fix = max(live, key=lambda r: r.get("trust_reduction", 0))
    exploit_fix = max(live, key=lambda r: r.get("exploit_reduction", 0))
    t_gain = trust_fix.get("trust_reduction", 0)
    e_gain = exploit_fix.get("exploit_reduction", 0)

    if t_gain <= 2 and e_gain <= 2:
        return ("No modelled action moves either channel by more than 2 points. "
                "This package is not where the next fix should go.")
    if e_gain <= 2:
        return (
            f'Every point of risk here sits in the trust channel. '
            f'"{ACTION_DESCRIPTION[trust_fix["action"]]}" removes '
            f'{t_gain} points of it. No modelled action reduces the exploit '
            f"channel, because there is no advisory to patch - which is exactly "
            f"why a CVSS-driven backlog would never schedule any work on this "
            f"package."
        )
    if t_gain <= 2:
        return (
            f'Risk here is entirely in the exploit channel. '
            f'"{ACTION_DESCRIPTION[exploit_fix["action"]]}" removes {e_gain} '
            f"points; the publishing path is already tight."
        )
    if trust_fix["action"] == exploit_fix["action"]:
        return (f'"{ACTION_DESCRIPTION[trust_fix["action"]]}" is the only action '
                f"that reduces both channels here "
                f"(trust -{t_gain}, exploit -{e_gain}).")
    return (
        f'"{ACTION_DESCRIPTION[trust_fix["action"]]}" cuts trust-channel exposure '
        f'by {t_gain} points but barely moves the exploit channel. '
        f'"{ACTION_DESCRIPTION[exploit_fix["action"]]}" does the opposite '
        f'({e_gain} points off the exploit channel). A CVSS-driven backlog would '
        f"only ever schedule the second one."
    )


def _finding(scored: dict, target: str) -> dict:
    for f in scored.get("findings", []):
        if f["id"] == target:
            return f
    return {}
