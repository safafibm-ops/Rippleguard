# Usage

## Starting a scan

Three ways to feed RippleGuard a project, from the left rail:

1. **Click a sample project.** Two ship with the repo — an Express API with
   floating ranges and a dev dependency with an install hook, and a
   "worm-exposure profile" whose every dependency appears on a published npm
   compromise IOC list.
2. **Paste a GitHub repository URL.** RippleGuard fetches
   `package.json`/lockfiles/`requirements.txt`/`pom.xml`/`.npmrc` from the
   repo root, plus up to 40 first-party source files for the reachability
   scan.
3. **Paste a manifest or SBOM directly** — pick the file type from the
   dropdown (`package.json`, a lockfile, `requirements.txt`, `pom.xml`, or a
   CycloneDX/SPDX SBOM) and paste its contents.

The left rail shows the pipeline's nine stages live as the scan runs (usually
a few seconds for a small project, longer for a large one gated by npm's
rate limits).

## Overview tab

Opens automatically when a scan completes.

- **Tiles** — portfolio risk, package count, advisory count, floating-range
  count, install-hook count, publishing-identity count, max depth, largest
  blast radius.
- **Rank inversion** — the two rankings side by side. Look for the
  highlighted row: a package with **no CVE at all** that still ranks near
  the top of the trust column, with a plain-English explanation of why.
- **Blast radius list** — every package, ranked by what a compromise of it
  would reach. Click any row to jump straight into the Simulation tab for
  that package.
- **Publishing identities** — who can push a new version of what's in your
  tree, and how many other packages they also control.

## Dependency graph tab

The full resolved graph as a force-directed layout. Node colour shows which
channel dominates that package's risk (blue = exploit, magenta = trust);
node size follows the RippleGuard score; a ring marks an install hook.
Click any node for its full evidence panel — every scoring component with
the exact fact behind it, plus buttons to jump into simulation or
remediation for that package.

Toggle **"High risk only"** to hide everything scoring under 40 and see just
the packages worth looking at.

## Compromise simulation tab

Pick a package, hit **Run simulation**, and watch the compromise propagate
through the graph hop by hop (the one deliberately-animated moment in the
app). The result panel shows packages/applications reached, blast-radius
arithmetic, and the highest-exposure propagation paths — each one naming its
weakest link, which is exactly the edge that pinning would cut.

## Remediation tab

Pick a package, hit **Model the fixes**, and get a table of all five
modelled actions with before/after scores for the whole tree, before/after
blast radius, and which channel each action actually addresses. The
recommended action is the one with the best risk-reduction-per-unit-effort —
not necessarily the one that removes the most points outright.

## Risk model tab

The exact weight table in force for this scan (also available raw at
`GET /api/model`), what each structural metric means in plain English, and a
full report of how the scan was actually resolved — which resolver was used,
how many packages got registry metadata, which sources degraded.

## Evaluation tab

Click **Run evaluation** to compare the trust-channel ranking against a
CVSS-only ranking on packages from the bundled seed IOC list
(`fixtures/iocs.json`). Reports ROC-AUC, average precision, and precision/
recall at k for all three rankings, plus how many ground-truth packages
actually appeared in your scan (the metric is only meaningful once some do —
try the "worm-exposure profile" sample for a scan where every dependency
qualifies).

## Example workflow

1. Load the **Express order API** sample.
2. On Overview, note the headline inversion — a package with zero CVEs
   ranking #1 by trust score because of a caret range and no lockfile.
3. Switch to Simulation, pick the top blast-radius package, run it, and read
   the propagation path to see which single dependency edge carries the
   most exposure.
4. Switch to Remediation for the same package — see that pinning collapses
   the trust score while upgrading (if a fix exists) does nothing for it,
   because the risk was never a catalogued vulnerability.
5. Switch to Evaluation and run it — with this sample, matches will be few or
   zero; switch to the **worm-exposure profile** sample instead to see a
   real, non-trivial ROC-AUC comparison.
