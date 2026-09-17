# Limitations

Stated plainly, in one place, rather than scattered as fine print. If a
feature works differently from what you'd assume, it's listed here.

## Reachability is an import-graph proxy, not function-level analysis

We check whether first-party code `import`s/`require`s a package, and
whether an identifier named in an advisory summary appears in that code.
We do **not** build a call graph, do not resolve which function is actually
invoked, and do not trace data flow. Endor Labs and OSV-Scanner do real
function-level reachability with a CVE-to-vulnerable-function database; that
requires infrastructure and data we don't have and couldn't build credibly
in a hackathon. Our proxy **over-reports** relative to a function-level tool
— every "IMPORTED" package looks reachable even if the vulnerable function
is never called. This is stated in the UI on every package detail panel, not
just here.

## Weights are heuristics, not calibrated

Every number in `docs/RISK_MODEL.md` reflects our judgment about the 2025–
2026 npm compromise campaigns, not a fitted model. We do not have labelled
training data connecting package features to confirmed compromises at scale.
The `/api/model` endpoint and the Risk Model tab say "calibrated: false"
explicitly, and every score in the UI is labelled "exposure," never
"probability" or "likelihood."

## deps.dev dependent counts are indicative, not exact

Google's own documentation for the `GetDependents` endpoint says the count
should be treated as indicative of relative popularity rather than precisely
accurate. We never present it as an exact figure.

## ecosyste.ms dependent lists are registry-declared, not install-resolved

A package appearing in another package's "dependent packages" list means
that package's manifest names it as a dependency — not that a real
`npm install` actually pulls both into the same tree together. The
ecosystem-reach portion of the compromise simulation inherits this
imprecision.

## Publisher fan-out is only resolved for npm, and only for a bounded set

Maintainer/publisher data comes from the npm registry, which rate-limits its
search endpoint hard. We bound the lookup to the 45 most-connected packages
and 60 unique identities per scan
(`graph/builder.py::MAINTAINER_LOOKUP_PACKAGES/BUDGET`) to stay under that
limit. Packages outside that budget score 0 on the publisher-fan-out
component, which understates their trust score. PyPI and Maven packages have
no maintainer layer at all — npm is the only registry that exposes this
cheaply.

## The IOC seed list is incomplete by design

`fixtures/iocs.json` ships with 37 packages drawn from public advisories
about the 2025–2026 npm compromise waves. The actual campaigns affected
500–800+ packages across several waves. We shipped a working, honestly-
labelled seed rather than a fabricated "complete" list. Use
`scripts/fetch_iocs.py` to extend it before treating any evaluation metric
as more than illustrative — and even a complete list only supports a proxy
evaluation (see next item).

## The evaluation harness measures a proxy, not ground-truth compromise

A package appearing on the IOC list means *a* malicious version of that
package was published at some point in one of the tracked campaigns. It does
**not** mean the specific version resolved in your scan is malicious. The
evaluation is asking "does the trust ranking prioritise packages that turned
out to be attractive worm targets," which is a real and useful question, but
it is not a malware-detection benchmark, and the UI states this caveat
directly next to every result.

## Remediation effort is an ordinal scale, not a cost estimate

The 1–5 effort figure in the Remediation tab is a plain judgment call (pin=1,
remove=5) with no monetary or time-estimate claim behind it. We deliberately
did not fabricate an engineering-hours or dollar figure, because we have no
real data to base one on.

## The dependency-graph resolver has real fallback boundaries

- Only npm has a from-scratch BFS fallback resolver; PyPI and Maven rely
  entirely on deps.dev, so if deps.dev is unreachable, those ecosystems fall
  back straight to lockfile-only (flat, no transitive edges).
- Our semver implementation (`ingest/ranges.py`) covers the common cases
  (exact, caret, tilde, comparator ranges, `||`, hyphen ranges) but is not a
  complete implementation of the npm semver specification — edge cases in
  build metadata or unusual prerelease tag ordering may resolve differently
  than npm's own resolver would.

## GitHub repository scanning is root-directory only

We fetch manifests and source files from the repository root as returned by
the default branch. We do not walk into subdirectories, and we do not handle
monorepo workspace structures (multiple `package.json` files, Lerna/Nx/
Turborepo configs) as a single unified scan.

## The force-directed graph layout doesn't scale past a few hundred nodes

`runForce` in `app.js` is an O(n²) repulsion simulation. It's genuinely fast
at the few-hundred-node scale a typical application produces (well under a
second), but would need spatial partitioning (a quadtree / Barnes-Hut
approximation) to stay responsive on a graph with several thousand nodes,
which large monorepos can produce.

## No persistence across restarts (beyond the HTTP cache)

Scan results live in an in-process dictionary (`pipeline.py::JOBS`) and are
lost on restart. Only the raw HTTP responses persist, in
`rippleguard-cache.sqlite`. There's no scan history, no saved reports, no
multi-user concept — this is a single-session analysis tool, not a
dashboard product.

## The optional LLM narration is deliberately limited

When enabled, the model sees only a JSON evidence bundle — no tools, no
broader context, no ability to search anything. Its output is rejected
outright if it names any package or advisory ID not present in that bundle.
This makes it safe but also means it can only rephrase what the deterministic
explanation already says; it cannot add insight beyond the computed evidence.
