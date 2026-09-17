"""
TRUST CHANNEL.

The question: "if an attacker published a malicious version of this package
right now, how much of that lands in my build without a human approving it?"

This is the channel that the 2025-2026 npm worm campaigns actually used, and
the one that CVE-based and reachability-based prioritisation is structurally
blind to. A malicious `postinstall` in an unreachable devDependency runs on
your CI machine; a reachability-first tool ranks that package near zero.

Every component below is measured, not assumed, and every component returns its
own points so the UI can show the arithmetic.
"""
from __future__ import annotations

import math
from datetime import datetime, timezone

from ..config import settings

WINDOW_DAYS = 30.0


def _recency_factor(published_at: str | None) -> tuple[float, str]:
    """Newly published versions sit inside the detection window.

    A malicious publish is typically caught within days-to-weeks by registry
    scanning and community reporting. A version published two years ago has
    been looked at by a lot of eyes; one published yesterday has not.
    """
    if not published_at:
        return 0.35, "publish date unknown"
    try:
        ts = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
    except ValueError:
        return 0.35, "publish date unparseable"
    age_days = (datetime.now(timezone.utc) - ts).total_seconds() / 86400.0
    if age_days <= 0:
        age_days = 0.0
    factor = max(0.0, 1.0 - (age_days / WINDOW_DAYS)) if age_days < WINDOW_DAYS else 0.05
    return round(factor, 4), f"published {int(age_days)} days ago"


def _fanout_factor(fanout: int) -> tuple[float, str]:
    """Log-scaled: one account controlling 500 packages vs 50 matters less than
    50 vs 5."""
    if not fanout:
        return 0.0, "publisher package count unavailable"
    factor = min(math.log1p(fanout) / math.log1p(1500), 1.0)
    return round(factor, 4), f"largest publisher also controls {fanout} registry packages"


def _hook_factor(node: dict, ignore_scripts: bool) -> tuple[float, str]:
    table = settings.floatiness
    has_hook = node.get("has_install_hook")
    scripts = node.get("install_scripts") or []
    if has_hook is None:
        return 0.45, "install-hook status unavailable for this ecosystem"
    if has_hook:
        if ignore_scripts:
            return (table.ignore_scripts_hook_factor,
                    f"declares {', '.join(scripts)} but .npmrc sets ignore-scripts=true")
        return 1.0, f"executes {', '.join(scripts)} during install"
    return (table.no_hook_residual,
            "no install hook; code still executes when the package is imported")


def _reach_factor(metrics: dict) -> tuple[float, str]:
    in_app = metrics.get("in_app_dependents") or 0
    eco = metrics.get("ecosystem_dependents") or 0
    local = math.log1p(in_app) / math.log1p(60)
    ecosystem = math.log1p(eco) / math.log1p(50_000)
    factor = min(max(local, ecosystem * 0.85), 1.0)
    bits = [f"{in_app} dependents inside this app"]
    if eco:
        bits.append(f"{eco:,} across the registry")
    return round(factor, 4), "; ".join(bits)


def score_package(
    node_id: str,
    node: dict,
    edge_from_app: dict | None,
    metrics: dict,
    *,
    ignore_scripts: bool = False,
) -> dict:
    """Return the trust-channel score (0-100) plus a full evidence bundle."""
    w = settings.trust

    # 1. Inheritance: would a malicious publish reach me automatically?
    if edge_from_app and "floatiness" in edge_from_app:
        float_factor = edge_from_app["floatiness"]
        float_reason = edge_from_app.get("floatiness_reason", "")
        spec = edge_from_app.get("spec", "")
        range_kind = edge_from_app.get("range_kind", "unknown")
    else:
        float_factor = 0.55
        float_reason = ("transitive dependency: inherits its parent's range, "
                        "not directly pinnable from this manifest")
        spec = node.get("declared_spec", "(transitive)")
        range_kind = "transitive"

    hook_factor, hook_reason = _hook_factor(node, ignore_scripts)
    fanout_factor, fanout_reason = _fanout_factor(metrics.get("maintainer_fanout", 0))
    recency_factor, recency_reason = _recency_factor(node.get("published_at"))
    reach_factor, reach_reason = _reach_factor(metrics)

    components = [
        {
            "factor": "Version floatiness",
            "weight": w.version_floatiness,
            "value": float_factor,
            "points": round(100 * w.version_floatiness * float_factor, 1),
            "evidence": f'declared as "{spec}" - {float_reason}',
            "meaning": "how automatically a new publish reaches your build",
        },
        {
            "factor": "Install-time execution",
            "weight": w.install_hook,
            "value": hook_factor,
            "points": round(100 * w.install_hook * hook_factor, 1),
            "evidence": hook_reason,
            "meaning": "whether malicious code runs before your code ever calls it",
        },
        {
            "factor": "Publisher fan-out",
            "weight": w.maintainer_fanout,
            "value": fanout_factor,
            "points": round(100 * w.maintainer_fanout * fanout_factor, 1),
            "evidence": fanout_reason,
            "meaning": "how many packages one compromised account would unlock",
        },
        {
            "factor": "Publish recency",
            "weight": w.publish_recency,
            "value": recency_factor,
            "points": round(100 * w.publish_recency * recency_factor, 1),
            "evidence": recency_reason,
            "meaning": "whether this version is still inside the detection window",
        },
        {
            "factor": "Downstream reach",
            "weight": w.downstream_reach,
            "value": reach_factor,
            "points": round(100 * w.downstream_reach * reach_factor, 1),
            "evidence": reach_reason,
            "meaning": "how far a compromise here would spread",
        },
    ]

    total = round(sum(c["points"] for c in components), 1)

    # Inheritance exposure on its own, reported separately because it is the
    # single number that answers "would I auto-inherit a malicious publish?"
    inheritance = round(float_factor * max(hook_factor, 0.3), 4)

    return {
        "score": min(total, 100.0),
        "components": components,
        "inheritance_exposure": inheritance,
        "range_kind": range_kind,
        "declared_spec": spec,
        "has_install_hook": node.get("has_install_hook"),
        "install_scripts": node.get("install_scripts") or [],
        "maintainers": node.get("maintainers") or [],
        "channel": "trust",
        "channel_question": (
            "If a malicious version were published right now, how much of it "
            "lands in your build automatically?"
        ),
    }
