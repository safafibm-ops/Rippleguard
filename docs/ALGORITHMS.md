# Algorithms

The maths behind every number the UI shows, in the order they run.

## 1. Version floatiness (`ingest/ranges.py::floatiness`)

Classifies a declared dependency specifier into a bucket and maps it to a
factor in `[0, 1]`:

| Range kind | Example | Factor |
|---|---|---|
| exact | `1.2.3` | 0.02 |
| tilde | `~1.2.3` | 0.45 |
| caret | `^1.2.3` | 0.80 |
| range/comparator | `>=1.2.3`, `1.x` | 0.85 |
| wildcard | `*`, `latest`, git ref | 1.00 |

If a lockfile entry with an integrity hash pins the resolution, the factor is
multiplied by `0.30` (a discount, never a zero — a lockfile makes `npm ci`
reproducible, but a range bump or a fresh `npm install` re-resolves it).

## 2. Semver resolution (`ingest/ranges.py`)

A minimal semver implementation (parse, caret/tilde bounds, comparator
matching, `||` alternation, hyphen ranges) used as the npm-registry-BFS
fallback resolver when deps.dev is unreachable. Not a full semver spec
implementation — see `docs/LIMITATIONS.md`.

## 3. CVSS v3.1 base score from vector string (`clients/osv.py::_score_from_vector`)

OSV frequently returns a CVSS vector string (`CVSS:3.1/AV:N/AC:L/...`) without
a pre-computed numeric score. We implement the published CVSS v3.1 base-score
equations directly:

```
ISS      = 1 - (1-C)(1-I)(1-A)
Impact   = 6.42 × ISS                                   (scope unchanged)
         = 7.52×(ISS-0.029) - 3.25×(ISS-0.02)^15         (scope changed)
Exploitability = 8.22 × AV × AC × PR × UI
Base     = min(1.08 × (Impact + Exploitability), 10)     (scope changed)
         = min(Impact + Exploitability, 10)              (scope unchanged)
```

rounded up to one decimal place, per spec. This lets RippleGuard rank
advisories by real severity instead of the three-bucket LOW/MEDIUM/HIGH
label, without needing a CVSS-scoring library.

## 4. Import-graph reachability (`reachability/imports.py`)

Regex-based extraction of `require()`/`import`/`from ... import` statements
from first-party source, mapped to three states:

- `PRESENT` (weight 0.25) — in the tree, never imported
- `IMPORTED` (weight 0.70) — imported by first-party code
- `SYMBOL_REFERENCED` (weight 1.00) — imported AND an identifier named in the
  advisory summary appears in that code

This is explicitly an **import-graph proxy**, not function-level call-graph
analysis — see `docs/LIMITATIONS.md` for what that means in practice.

## 5. Trust-channel score (`scoring/trust.py`)

Five weighted components (weights in `config.py::TrustWeights`), each
`100 × weight × factor`, summed:

```
score = 34% × floatiness
      + 26% × install_hook_factor
      + 16% × log1p(fanout) / log1p(1500)      [publisher fan-out, log-scaled]
      + 10% × recency_factor                    [1.0 at publish, decays over 30 days]
      + 14% × reach_factor                      [in-app + ecosystem dependents]
```

`inheritance_exposure` (reported separately, the single most important number)
is `floatiness × max(install_hook_factor, 0.3)` — "would a malicious publish
reach my build, and would it execute."

## 6. Exploit-channel score (`scoring/exploit.py`)

```
score = 55% × (worst_cvss / 10)
      + 30% × reachability_weight
      + 15% × depth_factor           [1.0 at depth 1, -0.15 per additional hop, floor 0.25]
```

## 7. Blend and rank inversion (`scoring/combine.py`)

```
score = 40% × exploit + 40% × trust + 20% × structural
```

If OSV is unreachable, the exploit weight is redistributed proportionally
onto trust and structural (never silently treated as zero — see
`docs/RISK_MODEL.md`).

`rank_inversion()` produces two independent orderings of the same finding
set — by worst CVSS (tie-broken by advisory count, then proximity — never by
trust score, or the two rankings would collapse into each other) and by
trust score — and reports the movement per package plus the largest upward
moves.

## 8. Structural criticality (`graph/metrics.py::structural_score`)

```
score = 30% × pagerank_share
      + 22% × min(betweenness × 4, 1)
      + 22% × log1p(in_app_dependents) / log1p(60)
      + 18% × log1p(ecosystem_dependents) / log1p(50000)
      +  8% × min(k_core / 6, 1)
```

Log-scaled because dependent counts are heavy-tailed — the jump from 3 to 30
dependents matters far more than 3,000 to 30,000. PageRank runs on the
**reversed** dependency graph, so importance flows from dependents to their
dependencies (a package many things depend on scores high).

## 9. Compromise propagation (`simulate/propagation.py`)

Modelled as **maximum-product path search**: transmission weight along an
edge is

```
w(dependent ← source) = inheritance(dependent, source) × channel(source)
channel(source) = 1.0 if source has an install hook, else 0.55
```

and a node's exposure is the *maximum* product of weights over any path from
the compromised package (not the sum — exposure asks "can it get here", not
"how many routes exist"). Implemented as Dijkstra over `-log(weight)`, since
minimising a sum of negative logs is equivalent to maximising a product.

Blast radius (`_blast_radius_score`) then combines coverage, exposure-weighted
reach, whether the application itself was hit, propagation depth, and public
registry dependent count into one 0–100 figure, explicitly labelled
"modelled exposure, not a probability."

## 10. Counterfactual remediation (`simulate/remediation.py`)

No formula — mechanical mutation of a deep-copied graph (pin an edge's
range, flip `has_install_hook` off tree-wide, swap in the OSV-reported fixed
version, cap transmission weight, or delete the exclusively-owned subtree),
followed by a full re-run of the real scoring pipeline (`rescore(graph)`).
Ranking rule: `risk_reduction / effort` (effort is a plain 1–5 ordinal, never
a fabricated cost figure).

## 11. Evaluation metrics (`evaluation/validate.py`)

Implemented from scratch, no `sklearn` dependency:

- **ROC-AUC** via the Mann-Whitney U rank-sum identity: sort all scores,
  assign mid-ranks to ties, then
  `AUC = (rank_sum_of_positives - n_pos(n_pos+1)/2) / (n_pos × n_neg)`.
- **Average precision**: for each positive found scanning top-down, accumulate
  `hits_so_far / rank`, averaged over the number of positives.
- **precision@k / recall@k**: exactly what they say, computed on the top-k by
  score.

Verified against known cases in `backend/tests/test_evaluation.py` (perfect
separation → AUC 1.0, inverted → 0.0, all-ties → 0.5).
