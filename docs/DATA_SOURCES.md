# Data Sources

Every external source RippleGuard talks to. All five are free and require no
API key. Every client in `backend/app/clients/` returns `None` on failure
rather than raising, and every failure is tracked per-source and surfaced in
the UI (`GET /api/health`, the "Data sources" panel in the left rail) — a
degraded scan always says so.

## npm registry — `registry.npmjs.org`

**Used for:** the abbreviated and full packument (`clients/npm_registry.py`),
which gives us install scripts, maintainers, publish timestamps, and
dependency lists. Also our fallback dependency resolver when deps.dev is
unreachable, and the `search?text=maintainer:<user>` endpoint for publisher
fan-out.

**If unavailable:** the entire trust channel loses its two richest signals
(install hooks, maintainer identities). RippleGuard falls back to
lockfile-only resolution if this is also the source of dependency
resolution.

**Rate limits observed:** the search endpoint (`maintainer:` lookups)
rate-limits aggressively (HTTP 429) under sustained load, which is why
publisher fan-out is bounded to the top 45 most-connected packages / 60
identities per scan (`graph/builder.py::MAINTAINER_LOOKUP_PACKAGES`).

## OSV.dev — `api.osv.dev`

**Used for:** vulnerability intelligence (`clients/osv.py`). Aggregates
GHSA, PyPA, RustSec, and distro advisories under one schema, keyed directly
by package + version — no CPE matching required. We batch-query up to 100
packages per request via `/v1/querybatch`, then fetch full detail only for
advisories that actually matched.

**If unavailable:** the entire exploit channel is unavailable for that scan.
The blend weight is redistributed onto trust and structural
(`scoring/combine.py::blend`) and the UI states explicitly that this is not
a clean bill of health.

## deps.dev (Google Open Source Insights) — `api.deps.dev`

**Used for:** `GetDependencies` (an authoritative, pre-resolved dependency
graph across npm/PyPI/Maven/Cargo/Go/NuGet — our primary resolver) and
`GetDependents` (a *count* of packages depending on a given version).

**Important limitation, stated in the UI:** the dependents endpoint returns
only a count, not the list, and Google's own documentation describes the
figure as indicative of relative popularity rather than exact. We do not
present it as a precise number anywhere.

**If unavailable:** RippleGuard falls back to npm-registry BFS resolution
(npm packages only), or lockfile-only resolution as a last resort.

## ecosyste.ms — `packages.ecosyste.ms`

**Used for:** the actual downstream dependent *package list* (not just a
count), which deps.dev doesn't provide. This is what makes the compromise
simulation's "reach across the public ecosystem" section possible — without
it, propagation could only walk downward from your own application, never
outward into the wider registry.

**Important limitation:** these lists are registry-declared dependents
(what a package's own manifest says depends on it), not install-resolved —
they can include packages that never actually get installed together in
practice.

**If unavailable:** the ecosystem-reach panel is empty for that scan; nothing
else depends on this source.

## GitHub Contents API — `api.github.com`

**Used for:** fetching manifests and up to 40 first-party source files when
you scan a repository URL instead of pasting a manifest directly.

**Rate limit:** 60 requests/hour unauthenticated, 5,000/hour with a
`GITHUB_TOKEN` (no scopes needed for public repos).

**If unavailable:** repository-URL scanning fails with a clear error; pasting
a manifest directly still works.

## What we deliberately did not integrate

- **GUAC** (OpenSSF) — a real, better-architected graph aggregator for
  exactly this problem, but it requires a self-hosted graph database and
  ingestion pipeline that a hackathon prototype can't stand up. Its "blast
  radius" concept is also a reverse lookup inside your own SBOM inventory,
  not the forward ecosystem simulation RippleGuard does.
- **OpenSSF Criticality Score / Scorecard** — repository-activity-based
  structural scoring, disconnected from any specific application's exposure.
  Our own structural metrics (PageRank, betweenness, in-app dependents) serve
  the same purpose scoped to the scanned application.
- **Socket / Phylum-style behavioural malware detection** (install-script
  static analysis, network-call detection in package code) — a legitimate
  and different problem (detecting malicious packages) from the one
  RippleGuard solves (scoring exposure to a malicious publish, known or
  unknown). Complementary, not overlapping.
