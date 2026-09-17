"""
EVALUATION HARNESS.

The claim RippleGuard makes is falsifiable: *a trust-channel ranking surfaces
packages that were actually hit by the 2025-2026 npm compromise campaigns
better than a CVSS ranking does.*

This module measures that claim rather than asserting it.

Ground truth = published indicator-of-compromise package lists (CISA alert,
vendor advisories). `fixtures/iocs.json` holds a small seed list that ships with
the repo; `scripts/fetch_iocs.py` documents how to extend it from the public
advisories. We do not include a fabricated list, and the harness reports the
size of the ground-truth set so nobody mistakes a 12-package seed for a
complete corpus.

Metrics implemented from scratch (no sklearn dependency):
  * precision@k
  * recall@k
  * ROC-AUC (via the Mann-Whitney U identity)
  * average precision (PR-AUC)
"""
from __future__ import annotations

import json
from pathlib import Path

from ..config import FIXTURES


def load_iocs(path: Path | None = None) -> dict:
    p = path or (FIXTURES / "iocs.json")
    if not p.exists():
        return {"packages": [], "source": "none", "note": "no IOC file present"}
    return json.loads(p.read_text())


def roc_auc(scores: list[float], labels: list[int]) -> float | None:
    """AUC via rank-sum. Returns None when one class is absent."""
    pos = [s for s, l in zip(scores, labels) if l == 1]
    neg = [s for s, l in zip(scores, labels) if l == 0]
    if not pos or not neg:
        return None
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks = [0.0] * len(scores)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    rank_sum = sum(r for r, l in zip(ranks, labels) if l == 1)
    return (rank_sum - len(pos) * (len(pos) + 1) / 2.0) / (len(pos) * len(neg))


def average_precision(scores: list[float], labels: list[int]) -> float | None:
    if sum(labels) == 0:
        return None
    order = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
    hits = 0
    total = 0.0
    for rank, idx in enumerate(order, start=1):
        if labels[idx] == 1:
            hits += 1
            total += hits / rank
    return total / sum(labels)


def precision_at_k(scores: list[float], labels: list[int], k: int) -> float:
    order = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:k]
    return sum(labels[i] for i in order) / max(1, len(order))


def recall_at_k(scores: list[float], labels: list[int], k: int) -> float | None:
    positives = sum(labels)
    if positives == 0:
        return None
    order = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:k]
    return sum(labels[i] for i in order) / positives


def evaluate_ranking(findings: list[dict], iocs: dict, ks=(5, 10, 20)) -> dict:
    """Compare three rankings on the same finding set.

    Labels: 1 if the package name appears in the published IOC list.

    IMPORTANT CAVEAT, reported in the output: a package appearing on an IOC list
    means a malicious *version* was published for it. It does not mean the
    version in this scan is malicious. This harness measures whether our ranking
    prioritises packages that turned out to be attractive worm targets - it is
    a proxy evaluation, not a detection benchmark.
    """
    ioc_names = {n.lower() for n in iocs.get("packages", [])}
    if not findings:
        return {"error": "no findings to evaluate"}

    labels = [1 if f["name"].lower() in ioc_names else 0 for f in findings]
    rankings = {
        "cvss_only": [f["exploit"].get("worst_cvss") or 0.0 for f in findings],
        "rippleguard_trust": [f["trust_score"] for f in findings],
        "rippleguard_blended": [f["rippleguard_score"] for f in findings],
    }

    out = {
        "ground_truth_packages": len(ioc_names),
        "ground_truth_source": iocs.get("source"),
        "matched_in_this_scan": sum(labels),
        "scanned_packages": len(findings),
        "rankings": {},
        "caveat": (
            "Presence on an IOC list means a malicious version of that package "
            "was published at some point, not that the version scanned here is "
            "malicious. This is a proxy evaluation of ranking quality, not a "
            "malware detection benchmark."
        ),
    }
    if sum(labels) == 0:
        out["verdict"] = (
            "No package in this scan appears on the bundled IOC list, so the "
            "rankings cannot be separated. Run against a project that depends "
            "on packages from the published compromise lists, or extend "
            "fixtures/iocs.json."
        )
        return out

    for name, scores in rankings.items():
        out["rankings"][name] = {
            "roc_auc": _round(roc_auc(scores, labels)),
            "average_precision": _round(average_precision(scores, labels)),
            **{f"precision_at_{k}": _round(precision_at_k(scores, labels, k))
               for k in ks},
            **{f"recall_at_{k}": _round(recall_at_k(scores, labels, k)) for k in ks},
        }

    a = out["rankings"]["cvss_only"]["roc_auc"]
    b = out["rankings"]["rippleguard_trust"]["roc_auc"]
    if a is not None and b is not None:
        delta = round(b - a, 3)
        out["verdict"] = (
            f"Trust-channel ROC-AUC {b} vs CVSS-only {a} (delta {delta:+}). "
            + ("Trust channel ranks known worm-target packages higher."
               if delta > 0 else
               "CVSS ranks them higher on this sample - reported as measured.")
        )
    return out


def _round(v):
    return None if v is None else round(v, 3)
