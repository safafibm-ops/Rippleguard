# Future Work

Ordered roughly by expected impact per unit effort.

## 1. Calibrate the risk model against real incident data

The single highest-value next step. Grow `fixtures/iocs.json` into a properly
reviewed, larger ground-truth set (via `scripts/fetch_iocs.py`, sourced from
CISA alerts and vendor write-ups), then fit a logistic regression or
gradient-boosted model over the same feature set instead of hand-set weights.
Backtest against campaigns excluded from training. This is what would turn
`docs/RISK_MODEL.md`'s "calibrated: false" into "calibrated: true."

## 2. Function-level reachability for the exploit channel

Replace the import-graph proxy with real call-graph analysis (à la Endor
Labs / OSV-Scanner), ideally by integrating an existing open-source call-graph
tool (Joern, or ecosystem-specific analysers) rather than building one from
scratch. This is the single biggest scope gap named in
`docs/LIMITATIONS.md`.

## 3. A real ground-truth benchmark for the trust channel

Beyond "does this package appear on an IOC list" — build a dataset that
tracks *which specific versions* were malicious, so the evaluation harness
can measure precision on a "would RippleGuard have flagged the exact
compromised version before it was publicly known" basis, not just a
package-level proxy.

## 4. Publisher fan-out for PyPI and Maven

Currently npm-only because it's the only registry with cheap
maintainer-lookup search. PyPI's JSON API exposes maintainer info per
project; Maven's Central Repository does not expose publisher identity
cleanly at all, so this would need ecosystem-specific approaches.

## 5. Monorepo and workspace support

Walk npm workspaces, Lerna/Nx/Turborepo configs, and multiple manifests in
subdirectories as one unified scan, rather than root-directory-only.

## 6. Historical trend tracking

Persist scan results (currently in-memory only) so a team can track whether
their trust-channel exposure is improving release over release — this is a
dashboard-product feature, deliberately out of scope for a single-session
analysis prototype.

## 7. CI/CD integration

A GitHub Action or pre-commit hook that runs the same pipeline and fails a
PR when a new dependency crosses a trust-score threshold, particularly for
newly-added install hooks or a sudden switch from a pinned to a floating
range.

## 8. Spatial partitioning for the graph renderer

Swap the O(n²) force simulation for a Barnes-Hut quadtree approximation to
stay responsive on graphs with thousands of nodes (large monorepos), per
`docs/LIMITATIONS.md`.

## 9. Cross-ecosystem propagation

Currently, compromise simulation propagates within one dependency graph.
A package published to both npm and a vendored copy in a different
ecosystem (or a supply chain that crosses from a build tool into an
application) isn't modelled as a single connected risk today.

## 10. Richer LLM narration, still grounded

Extend the evidence bundle the model sees (e.g. the top propagation paths,
comparable packages in the same scan) while keeping the same hard
grounding-validation rule — never loosen "reject any name not in the
bundle" in the name of a richer narrative.
