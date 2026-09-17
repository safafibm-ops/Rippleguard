"""Graph construction, dual-channel scoring, propagation and counterfactuals.

These run on a hand-built graph so they need no network, which keeps the test
suite deterministic and fast.
"""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import networkx as nx
import pytest

from app.graph import metrics as gmetrics
from app.graph.builder import APP, MAINTAINER, PACKAGE
from app.scoring import combine, exploit, trust
from app.simulate.propagation import simulate
from app.simulate.remediation import apply_action, evaluate


def toy_graph():
    """app -> hooked (caret, install hook) and safe (pinned); hub is shared."""
    g = nx.DiGraph()
    g.add_node("app:demo@1.0.0", kind=APP, name="demo", version="1.0.0")
    g.add_node("npm:hooked@1.0.0", kind=PACKAGE, ecosystem="npm", name="hooked",
               version="1.0.0", direct=True, scope="runtime",
               has_install_hook=True, install_scripts=["postinstall"],
               maintainers=["alice"], published_at=None)
    g.add_node("npm:safe@2.0.0", kind=PACKAGE, ecosystem="npm", name="safe",
               version="2.0.0", direct=True, scope="runtime",
               has_install_hook=False, install_scripts=[], maintainers=["bob"])
    g.add_node("npm:hub@3.0.0", kind=PACKAGE, ecosystem="npm", name="hub",
               version="3.0.0", direct=False, scope="runtime",
               has_install_hook=False, install_scripts=[], maintainers=["alice"])
    g.add_edge("app:demo@1.0.0", "npm:hooked@1.0.0", kind="DEPENDS_ON",
               spec="^1.0.0", floatiness=0.80, range_kind="caret",
               floatiness_reason="floats on minor releases", scope="runtime")
    g.add_edge("app:demo@1.0.0", "npm:safe@2.0.0", kind="DEPENDS_ON",
               spec="2.0.0", floatiness=0.02, range_kind="exact",
               floatiness_reason="pinned", scope="runtime")
    # hooked floats on hub; safe pins it. Same shared dependency, different
    # inheritance exposure - which is exactly what the model should distinguish.
    g.add_edge("npm:hooked@1.0.0", "npm:hub@3.0.0", kind="DEPENDS_ON",
               spec="^3.0.0", floatiness=0.80, range_kind="caret",
               floatiness_reason="floats on minor releases", scope="runtime")
    g.add_edge("npm:safe@2.0.0", "npm:hub@3.0.0", kind="DEPENDS_ON",
               spec="3.0.0", floatiness=0.02, range_kind="exact",
               floatiness_reason="pinned", scope="runtime")
    g.add_node("maintainer:alice", kind=MAINTAINER, name="alice",
               packages_controlled=400)
    g.add_edge("maintainer:alice", "npm:hooked@1.0.0", kind="PUBLISHES")
    g.add_edge("maintainer:alice", "npm:hub@3.0.0", kind="PUBLISHES")
    return g


# ---------------------------------------------------------------- metrics --

def test_metrics_identify_the_hub():
    g = toy_graph()
    m = gmetrics.compute(g)
    assert m["npm:hub@3.0.0"]["in_app_dependents"] > m["npm:safe@2.0.0"]["in_app_dependents"]
    assert m["npm:hooked@1.0.0"]["depth"] == 1
    assert m["npm:hub@3.0.0"]["depth"] == 2
    assert m["npm:hub@3.0.0"]["maintainer_fanout"] == 400


def test_maintainer_blast_radius_ranks_by_control():
    rows = gmetrics.maintainer_blast_radius(toy_graph())
    assert rows[0]["maintainer"] == "alice"
    assert rows[0]["packages_in_this_app"] == 2


# ----------------------------------------------------------------- trust ---

def test_install_hook_and_caret_beat_a_pinned_package():
    """The central claim of the trust channel, as an assertion."""
    g = toy_graph()
    m = gmetrics.compute(g)
    app = "app:demo@1.0.0"
    hooked = trust.score_package("npm:hooked@1.0.0", g.nodes["npm:hooked@1.0.0"],
                                 g.get_edge_data(app, "npm:hooked@1.0.0"),
                                 m["npm:hooked@1.0.0"])
    safe = trust.score_package("npm:safe@2.0.0", g.nodes["npm:safe@2.0.0"],
                               g.get_edge_data(app, "npm:safe@2.0.0"),
                               m["npm:safe@2.0.0"])
    assert hooked["score"] > safe["score"]
    assert hooked["inheritance_exposure"] > safe["inheritance_exposure"]


def test_ignore_scripts_collapses_the_hook_factor():
    g = toy_graph()
    m = gmetrics.compute(g)
    edge = g.get_edge_data("app:demo@1.0.0", "npm:hooked@1.0.0")
    on = trust.score_package("npm:hooked@1.0.0", g.nodes["npm:hooked@1.0.0"],
                             edge, m["npm:hooked@1.0.0"], ignore_scripts=False)
    off = trust.score_package("npm:hooked@1.0.0", g.nodes["npm:hooked@1.0.0"],
                              edge, m["npm:hooked@1.0.0"], ignore_scripts=True)
    assert off["score"] < on["score"]


def test_trust_components_sum_to_the_score():
    g = toy_graph()
    m = gmetrics.compute(g)
    r = trust.score_package("npm:hooked@1.0.0", g.nodes["npm:hooked@1.0.0"],
                            g.get_edge_data("app:demo@1.0.0", "npm:hooked@1.0.0"),
                            m["npm:hooked@1.0.0"])
    assert abs(sum(c["points"] for c in r["components"]) - r["score"]) < 0.2


# --------------------------------------------------------------- exploit ---

def test_reachability_changes_the_exploit_score():
    vuln = [{"id": "GHSA-x", "cve": "CVE-2024-1", "cvss": 9.8,
             "severity_label": "CRITICAL", "cvss_vector": "", "summary": "",
             "fixed_version": "1.0.1"}]
    m = {"depth": 1}
    high = exploit.score_package("p", {}, vuln,
                                 {"weight": 1.0, "explanation": "x"}, m)
    low = exploit.score_package("p", {}, vuln,
                                {"weight": 0.25, "explanation": "y"}, m)
    assert high["score"] > low["score"]


def test_no_vulns_means_zero_exploit_score():
    r = exploit.score_package("p", {}, [], {"weight": 1.0}, {"depth": 1})
    assert r["score"] == 0.0 and r["vulnerabilities"] == []


def test_blend_reweights_when_osv_is_down():
    with_osv, _, note_a = combine.blend(80, 40, 50, osv_available=True)
    without, breakdown, note_b = combine.blend(0, 40, 50, osv_available=False)
    assert note_a == "" and "OSV unreachable" in note_b
    assert all(b["factor"] != "Exploit channel" for b in breakdown)
    assert without > combine.blend(0, 40, 50, osv_available=True)[0], \
        "dropping OSV must not silently deflate the score"


# ----------------------------------------------------------- propagation ---

def test_simulation_reaches_the_application():
    g = toy_graph()
    r = simulate(g, "npm:hub@3.0.0")
    assert r["is_simulation"] is True
    assert r["reached_applications"] == 1
    assert r["reached_packages"] == 2
    assert 0 < r["application_exposure"] <= 1


def test_pinned_edges_transmit_less_than_caret_edges():
    """Two packages depend on the same hub. The one that pins it must absorb
    less exposure from a hub compromise than the one that floats on it."""
    g = toy_graph()
    r = simulate(g, "npm:hub@3.0.0")
    by_id = {x["id"]: x["exposure"] for x in r["reached"]}
    assert by_id["npm:hooked@1.0.0"] > by_id["npm:safe@2.0.0"]


def test_pinning_an_edge_cuts_the_path_it_sits_on():
    """The counterfactual claim, as an assertion: pinning reduces the modelled
    blast radius of the package that was pinned."""
    g = toy_graph()
    before = simulate(g, "npm:hub@3.0.0")["blast_radius"]["score"]
    pinned, _ = apply_action(g, "npm:hub@3.0.0", "pin")
    after = simulate(pinned, "npm:hub@3.0.0")["blast_radius"]["score"]
    assert after < before


def test_unknown_node_raises():
    with pytest.raises(KeyError):
        simulate(toy_graph(), "npm:nope@0.0.0")


# ----------------------------------------------------------- remediation ---

def _rescore(g):
    m = gmetrics.compute(g)
    app = next((n for n, d in g.nodes(data=True) if d.get("kind") == APP), None)
    findings = []
    for nid, node in g.nodes(data=True):
        if node.get("kind") != PACKAGE:
            continue
        nm = m.get(nid, {})
        edge = g.get_edge_data(app, nid)
        if edge is None:
            inc = [d for _u, _v, d in g.in_edges(nid, data=True) if "floatiness" in d]
            edge = max(inc, key=lambda d: d["floatiness"]) if inc else None
        t = trust.score_package(nid, node, edge, nm)
        e = exploit.score_package(nid, node, [], {"weight": 0.25}, nm)
        s, _ = gmetrics.structural_score(nm)
        total, _, _ = combine.blend(e["score"], t["score"], s, True)
        findings.append({"id": nid, "rippleguard_score": total,
                         "exploit_score": e["score"], "trust_score": t["score"]})
    return {"findings": findings, "portfolio_score": 0.0}


def test_pin_action_reduces_trust_score():
    g = toy_graph()
    before = {f["id"]: f for f in _rescore(g)["findings"]}
    pinned, log = apply_action(g, "npm:hub@3.0.0", "pin")
    after = {f["id"]: f for f in _rescore(pinned)["findings"]}
    assert after["npm:hub@3.0.0"]["trust_score"] < before["npm:hub@3.0.0"]["trust_score"]
    assert log


def test_remove_action_deletes_exclusively_owned_subtree():
    g = toy_graph()
    removed, _ = apply_action(g, "npm:hooked@1.0.0", "remove")
    assert "npm:hooked@1.0.0" not in removed
    assert "npm:hub@3.0.0" in removed, "hub is shared with safe, so it must survive"


def test_evaluate_returns_every_action_with_a_verdict():
    out = evaluate(toy_graph(), "npm:hooked@1.0.0", _rescore)
    actions = {o["action"] for o in out["options"]}
    assert actions == {"pin", "ignore_scripts", "upgrade", "isolate", "remove"}
    assert out["recommended"] in actions
    for o in out["options"]:
        assert "fixes_channel" in o and "risk_reduction" in o


def test_original_graph_is_never_mutated():
    g = toy_graph()
    spec_before = g["app:demo@1.0.0"]["npm:hooked@1.0.0"]["spec"]
    apply_action(g, "npm:hooked@1.0.0", "pin")
    assert g["app:demo@1.0.0"]["npm:hooked@1.0.0"]["spec"] == spec_before
