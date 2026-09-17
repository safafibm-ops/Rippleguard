# RippleGuard

**A dual-channel software supply-chain risk analyser.** It scores every
dependency in your application twice — once for known vulnerabilities, once
for how exposed it is to a malicious publish — and shows you where those two
rankings disagree.

Built for a cybersecurity hackathon by Team Brute Force.

## Why this exists

Every scanner on the market (Snyk, Socket, OSV-Scanner, GitHub Dependabot)
answers one question: *is there a known vulnerability here, and can my code
reach it?* That question is well solved. It is also the wrong question for
the attacks that actually happened in 2025–2026.

The Shai-Hulud npm worm waves, the `chalk`/`debug` maintainer compromise, and
the `@ctrl/tinycolor` incident did not exploit a CVE. They compromised a
publishing identity and shipped a malicious version through the ecosystem's
own trust model — often via a `postinstall` script that runs during
`npm install`, whether or not your code ever imports the package. A
reachability-first scanner is structurally blind to that: it ranks an
unreached devDependency near zero, which is exactly backwards when the risk
is in the install step, not the import.

RippleGuard adds the missing question: **if a malicious version of this
package were published right now, how much of it lands in your build
automatically?** We call that **inheritance exposure**, and it's computable
directly from your manifest — no threat intelligence feed required.

## What it does

1. **Resolves your real dependency graph** (deps.dev → npm registry BFS →
   lockfile, in that fallback order) across npm, PyPI, and Maven.
2. **Scores two channels per package**: the *exploit channel* (known CVE +
   reachability, like every other tool) and the *trust channel* (version
   floatiness, install hooks, publisher fan-out, publish recency,
   downstream reach — like nothing else).
3. **Shows you the rank inversion** — packages with zero CVEs that rank #1 on
   the publishing-risk axis, which a CVSS-first backlog would never schedule.
4. **Simulates a compromise** — pick any package, and RippleGuard propagates
   a hypothetical malicious publish through the graph and measures blast
   radius, both inside your app and across the public ecosystem.
5. **Models five remediations** (pin / disable install scripts / upgrade /
   isolate / remove) by actually re-running the scoring pipeline on a mutated
   copy of the graph — not by estimating.
6. **Measures itself.** The evaluation view compares the trust-channel
   ranking against a CVSS-only ranking on packages from published npm
   compromise campaigns, using ROC-AUC and precision@k computed from scratch.

## Quickstart

```bash
./run.sh
```

Then open **http://127.0.0.1:8000** and click one of the two sample projects
in the left rail. No API keys are required — RippleGuard runs entirely
against free, keyless public data sources (OSV, deps.dev, ecosyste.ms, the
npm registry).

See [`docs/SETUP.md`](docs/SETUP.md) for manual setup, environment variables,
and troubleshooting.

## Where to go next

| Doc | What's in it |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | System design, module map, data flow |
| [`docs/FEATURES.md`](docs/FEATURES.md) | Every feature, what it does, what's real |
| [`docs/SETUP.md`](docs/SETUP.md) | Install, run, configure |
| [`docs/USAGE.md`](docs/USAGE.md) | Walkthrough of a real scan |
| [`docs/ALGORITHMS.md`](docs/ALGORITHMS.md) | The maths behind every score |
| [`docs/RISK_MODEL.md`](docs/RISK_MODEL.md) | Every weight, and why it's that value |
| [`docs/DATA_SOURCES.md`](docs/DATA_SOURCES.md) | Every API this project calls |
| [`docs/DEMO.md`](docs/DEMO.md) | A 4-minute hackathon demo script |
| [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) | What this prototype does *not* do |
| [`docs/FUTURE_WORK.md`](docs/FUTURE_WORK.md) | What we'd build next |

## Project layout

```
rippleguard/
├── backend/
│   ├── app/
│   │   ├── clients/       # npm registry, OSV, deps.dev, ecosyste.ms, GitHub
│   │   ├── ingest/        # manifest/SBOM parsing, semver range analysis
│   │   ├── graph/         # dependency graph builder + structural metrics
│   │   ├── scoring/       # trust channel, exploit channel, blend
│   │   ├── simulate/      # compromise propagation, counterfactual remediation
│   │   ├── reachability/  # import-graph reachability proxy
│   │   ├── explain/       # deterministic + optional LLM explanations
│   │   ├── evaluation/    # ROC-AUC / precision@k harness
│   │   ├── pipeline.py    # orchestrates one scan end to end
│   │   ├── config.py      # every weight and setting, in one place
│   │   └── main.py        # FastAPI app
│   └── tests/             # 38 unit tests, no network required
├── frontend/               # zero-build HTML/CSS/JS console
├── fixtures/               # two sample projects + a seed IOC list
├── scripts/fetch_iocs.py   # extend the evaluation ground truth
├── run.sh                  # one-command launcher
└── requirements.txt
```

## Tests

```bash
pytest        # 38 tests, no network access needed, runs in well under a second
```
