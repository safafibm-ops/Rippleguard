# Architecture

## Stack, and why

| Layer | Choice | Why |
|---|---|---|
| Backend | **FastAPI + async httpx** | The analysis is dominated by fan-out HTTP (hundreds of registry/OSV calls per scan). `asyncio.gather` makes that concurrent for free; FastAPI gives us request validation and background-task scheduling with almost no boilerplate. |
| Graph engine | **NetworkX** | PageRank, betweenness centrality, k-core, and shortest-path are all one-line calls. Re-implementing graph algorithms would have spent the hackathon's time in the wrong place. |
| Frontend | **Vanilla HTML/CSS/JS, zero build step** | No npm install, no bundler, no CDN dependency — the whole app is three static files FastAPI serves directly. It works offline after one scan (see caching, below) and a judge can read `app.js` top to bottom without a build tool. |
| Dependency graph rendering | **Hand-written force-directed SVG layout** | A from-scratch spring/repulsion simulation (`runForce` in `app.js`) rather than D3 or a CDN graph library, to keep the zero-dependency guarantee. |
| Cache | **SQLite** (stdlib `sqlite3`) | One file, no server process, survives restarts. Every upstream HTTP response is cached by URL+headers, so a repeat scan during a live demo needs zero network round-trips. |

No database beyond the cache, no message queue, no separate frontend build —
deliberately, so the whole thing is `git clone && ./run.sh`.

## Module map

```
backend/app/
├── config.py              Every weight and setting, as plain dataclasses.
│                           Exposed verbatim via GET /api/model.
├── clients/                One file per external API. Every client returns
│   ├── base.py             None on failure, never raises past this layer.
│   ├── npm_registry.py     base.py's Fetcher wraps every call in the SQLite
│   ├── osv.py              cache and a per-source health tracker, so a scan
│   ├── depsdev.py          can report exactly which of its five upstream
│   ├── ecosystems.py       APIs were reachable.
│   └── github.py
├── ingest/
│   ├── manifest.py         package.json/lockfiles/requirements.txt/pom.xml/
│   │                        CycloneDX+SPDX SBOM -> a normalised Project.
│   └── ranges.py           Semver parsing + the floatiness() function that
│                            is the core input to the trust channel.
├── graph/
│   ├── builder.py          Project -> a NetworkX multi-layer graph (app,
│   │                        package, maintainer, vuln nodes). Three-tier
│   │                        resolver fallback: deps.dev -> npm BFS -> lockfile.
│   └── metrics.py          PageRank / betweenness / k-core / depth /
│                            maintainer fan-out, plus structural_score().
├── reachability/
│   └── imports.py          Parses first-party source for import statements.
│                            Labelled honestly as an import-graph proxy, not
│                            function-level call-graph analysis.
├── scoring/
│   ├── trust.py             THE differentiator. Inheritance exposure,
│   │                        install hooks, publisher fan-out, recency, reach.
│   ├── exploit.py           CVSS + reachability + depth - what every other
│   │                        tool already does.
│   └── combine.py           Blends the two channels; computes rank_inversion.
├── simulate/
│   ├── propagation.py       "If X were compromised" - weighted Dijkstra over
│   │                        -log(transmission weight), i.e. maximise the
│   │                        product of edge weights along a path.
│   └── remediation.py       Mutates a deep copy of the graph per action,
│                            re-runs the SAME scoring pipeline, diffs the result.
├── explain/
│   ├── templates.py         Deterministic, always-on explanation generator.
│   └── llm.py                Optional narration; output is rejected if it
│                            names anything not in the evidence bundle.
├── evaluation/
│   └── validate.py           ROC-AUC / average precision / precision@k /
│                            recall@k, implemented from scratch (no sklearn).
├── pipeline.py                Orchestrates one scan end to end; exposes
│                             make_rescorer(), a pure function of the graph
│                             shared between the initial scan and the
│                             counterfactual remediation engine.
└── main.py                    FastAPI routes. Serves the frontend too.
```

## Data flow through one scan

```
manifest / SBOM / GitHub repo URL
        │
        ▼
ingest/manifest.py  ──────────────►  Project (declared deps, ranges,
                                       lockfile integrity, .npmrc flags)
        │
        ▼
graph/builder.py
   1. deps.dev GetDependencies (resolved graph, multi-ecosystem)
   2. npm registry BFS with our own semver resolver     [fallback]
   3. lockfile versions only, no transitive edges        [fallback]
        │
        ▼
graph/builder.attach_registry_metadata()  ──►  install hooks, maintainers,
                                                 publish dates (npm only)
        │
        ▼
clients/osv.enrich()  ──►  graph/builder.attach_vulnerabilities()
        │
        ▼
graph/builder.attach_ecosystem_reach()  ──►  deps.dev dependent counts +
                                               ecosyste.ms dependent lists
        │
        ▼
reachability/imports.extract_imports()  (first-party source, if supplied)
        │
        ▼
pipeline.make_rescorer()  — a closure over (project, imports, sources,
osv_availability) that is a PURE FUNCTION OF THE GRAPH:

    for each package node:
        reachability = reachability/imports.classify(...)
        exploit      = scoring/exploit.score_package(...)
        trust        = scoring/trust.score_package(...)
        structural   = graph/metrics.structural_score(...)
        total        = scoring/combine.blend(...)
        │
        ▼
scoring/combine.rank_inversion()  — CVSS ranking vs trust ranking
simulate/propagation.rank_by_blast_radius()  — simulate every package
        │
        ▼
JSON result, cached in memory by scan id, served to the frontend
```

The `rescore(graph)` closure is the single most important design decision in
the backend: because it takes a graph and returns findings with no other
state, `simulate/remediation.py` can deep-copy the graph, mutate it (pin a
version, disable install scripts, upgrade to a fixed version, ...), call the
exact same closure, and diff the result. The "after" numbers in the
Remediation tab are never estimated — they come from the same code path as
the "before" numbers.

## Frontend architecture

Six views share one `state` object (`scanId`, `result`, `graph`, `sim`) in
`app.js`. There is no framework and no virtual DOM: every render function
sets `.innerHTML` on a container from a template literal. This is a
deliberate trade for a hackathon prototype — it keeps the mental model to
"data in, HTML string out" with zero build tooling, at the cost of not
scaling to a much larger app.

The dependency graph (`#graph` SVG) runs a genuine force-directed layout
(`runForce`): O(n²) repulsion + spring attraction + centering force, 260
iterations with cooling, computed once per scan. At the few hundred nodes a
typical scan produces this finishes in well under a second; it would need a
quadtree (Barnes-Hut) to scale to thousands of nodes, which is out of scope
here (see `docs/LIMITATIONS.md`).

## Why a rescore closure instead of a class

An object-oriented "Scanner" class with mutable state was the obvious
alternative. We rejected it because the counterfactual engine's entire value
proposition is "the same code produced both numbers." A closure over
immutable inputs (`project`, `imported`, `source_files`, `osv_available`)
that takes the one thing that changes (the graph) as its only argument makes
that guarantee structural rather than a comment asking future-us to keep two
code paths in sync.
