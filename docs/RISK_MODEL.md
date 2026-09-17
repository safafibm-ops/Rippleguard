# Risk Model

**None of the weights below are empirically calibrated.** They are prototype
heuristics chosen to reflect the relative importance we believe each signal
carries, based on the 2025–2026 npm compromise campaigns described in
`docs/DATA_SOURCES.md`. The evaluation harness (`docs/ALGORITHMS.md` §11,
Evaluation tab in the UI) is how you test whether they actually work, rather
than taking this document's word for it.

This exact table is served live at `GET /api/model` and rendered in the
Risk Model tab, so the UI never says anything different from this file.

## Trust channel — weights sum to 1.00

| Component | Weight | Why this weight |
|---|---:|---|
| Version floatiness | **0.34** | The single biggest lever. It is the direct answer to "would a malicious publish reach my build automatically" and is knowable with certainty from the manifest alone — no external intelligence needed. |
| Install-time execution | **0.26** | This is the mechanism the 2025–2026 worm waves actually used (`postinstall` scripts). Weighted second-highest because it converts "reaches the build" into "executes code," which reachability-based tools cannot see at all. |
| Publisher fan-out | **0.16** | Real but indirect — a large fan-out means a compromised account is *more attractive* and more damaging, not that this specific package is more likely to be the one compromised. |
| Publish recency | **0.10** | A meaningful but time-decaying signal (30-day window); weighted lowest of the five because publish date alone says little once a package is a few weeks old. |
| Downstream reach | **0.14** | Amplification, not likelihood — included so a highly-connected hub scores somewhat higher, but capped below floatiness and install-hooks so popularity alone can't dominate the score. |

## Exploit channel — weights sum to 1.00

| Component | Weight | Why |
|---|---:|---|
| Advisory severity | **0.55** | The primary signal every existing tool already uses; we keep it dominant here deliberately, so the exploit channel behaves the way a reviewer expects a CVSS-driven tool to behave. |
| Reachability (import proxy) | **0.30** | Meaningful discount for genuinely unreached code, without letting an unreachability *proxy* zero out a real vulnerability, since our reachability signal is coarser than function-level analysis (see `docs/LIMITATIONS.md`). |
| Exposure depth | **0.15** | Smallest weight — depth is a coarse proxy for "how easy is attacker-controlled input to drive into this code," worth some points but not many. |

## Blend weights

```
40% exploit channel + 40% trust channel + 20% structural criticality
```

**Exploit and trust are weighted equally on purpose.** This is the project's
central bet: a CVE-first tool implicitly weights exploit at 100%. Splitting
evenly says "we believe these two attack surfaces deserve equal attention,"
which is precisely the claim the evaluation harness lets you check against
real incident data.

**If OSV is unreachable**, the exploit weight (40%) is not dropped or scored
as zero — it is redistributed proportionally onto trust and structural
(`scoring/combine.py::blend`), so a scan run on a network without OSV access
does not silently produce a lower, falsely-reassuring score. The UI states
this explicitly whenever it happens.

## Version floatiness table

| Range kind | Factor | Rationale |
|---|---:|---|
| Exact (`1.2.3`) | 0.02 | Near-zero, not zero: a human still has to bump it, but typo-driven or automated version bumps happen. |
| Tilde (`~1.2.3`) | 0.45 | Patch-level drift only. |
| Caret (`^1.2.3`) | 0.80 | npm's own default range operator — most declared dependencies use this, and it accepts any minor/patch bump. |
| Comparator (`>=1.2.3`, `1.x`) | 0.85 | Open-ended; slightly floatier than caret since there's no upper bound assumption at all. |
| Wildcard / `latest` / untagged git ref | 1.00 | Maximum: the very next publish is picked up with zero review. |
| Lockfile discount | ×0.30 | A discount, never an exemption — see `docs/ALGORITHMS.md` §1 for why a lockfile doesn't zero this out. |
| `.npmrc ignore-scripts=true` | install-hook factor → 0.05 | Nearly eliminates the install-time-execution component; residual because a package still executes at import/runtime. |
| No install hook | residual 0.30 | Even without an install hook, imported code still runs — this is not zero. |

## What calibration would look like

We do not have labelled training data — that's the honest reason these are
heuristics rather than fitted weights. A real calibration pass would need:

1. A larger, reviewed ground-truth set of confirmed supply-chain compromises
   (see `docs/FUTURE_WORK.md` and `scripts/fetch_iocs.py`).
2. A logistic regression or gradient-boosted model over the same feature set,
   trained to predict "was this package's publishing surface actually
   exploited" rather than hand-set weights.
3. Backtesting against campaigns the model wasn't trained on, not the ones
   used to pick weights.

Until then, every score in this app is a heuristic ranking signal, not a
calibrated risk probability, and the UI never calls it one.
