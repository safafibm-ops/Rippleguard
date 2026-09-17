# Demo Script

A ~4-minute walkthrough for judges. Run `./run.sh` and have
**http://127.0.0.1:8000** open before you start talking.

## 0:00 – The hook (30s)

> "Every supply-chain scanner on the market asks one question: is there a
> known vulnerability here, and can my code reach it? That question is
> already solved — Snyk, Socket, OSV-Scanner all do it well. It's also the
> wrong question for the attacks that actually happened in the last year."

> "The npm worm campaigns — Shai-Hulud, the chalk/debug compromise,
> tinycolor — didn't exploit a CVE. They compromised a publishing identity
> and shipped a malicious version through the registry's own trust model.
> Often through an install script that runs before your code ever touches
> the package."

Click the **Express order API** sample.

## 0:30 – The rank inversion (60s)

While it scans (a few seconds), narrate the pipeline stages ticking by in
the left rail — "real npm registry calls, real OSV queries, happening now."

Once it lands on Overview:

> "Here's the headline. Left column: how a CVSS-first tool would rank these
> 300-odd packages. Right column: RippleGuard's trust channel."

Point at the highlighted headline-inversion package.

> "This package has **zero** known vulnerabilities. A CVSS tool would never
> show it to you. It's #1 on our trust ranking because it's on a floating
> caret range, there's no lockfile pinning it, and its publisher also
> controls hundreds of other packages. That's the exact shape of a
> Shai-Hulud-style attack."

## 1:30 – Simulation (60s)

Switch to **Compromise simulation**, pick the top blast-radius package, hit
Run.

> "Suppose this were compromised right now. We propagate that hypothetically
> through the graph — not summing paths, taking the strongest one — and
> measure how far it would spread."

Point at the propagation path.

> "It reaches the application in five hops. This edge here is the weakest
> link — the exact place pinning would cut the path."

## 2:30 – Remediation (45s)

Switch to **Remediation**, model the fixes for the same package.

> "Five real fixes, each one actually re-scored through the same pipeline —
> not estimated. Watch: pinning collapses the trust score and the blast
> radius. Upgrading does almost nothing, because there's no CVE to patch.
> A CVSS-driven backlog would schedule the fix that does nothing, and skip
> the one that matters."

## 3:15 – Evaluation, the credibility moment (45s)

Switch to the **worm-exposure profile** sample, then **Evaluation**, run it.

> "We don't just claim the trust ranking is better — we measure it. This
> project's every dependency appears on a published npm compromise list.
> Trust-channel ROC-AUC comes in measurably above CVSS-only on this sample.
> That's not a design claim, that's a number computed live, right now,
> against real incident data."

## 4:00 – Close (15s)

> "Everything you just saw is real: live npm and OSV data, real CVSS parsing,
> a real force-directed graph, zero mocked numbers anywhere. The weights
> aren't calibrated yet — we say so, right in the Risk Model tab — but the
> evaluation harness is how you'd prove they should be."

## If something's offline during the demo

Set `RG_OFFLINE=true` after doing one successful scan online to pre-warm the
SQLite cache (`rippleguard-cache.sqlite`), and every subsequent scan of the
same sample projects replays instantly from cache with no network dependency
at all — a genuine safety net for flaky venue wifi.

## Fallback talking point if OSV/deps.dev is blocked on venue wifi

This has actually happened in testing (some sandboxed/corporate networks
403 everything except the npm registry). If it happens live:

> "OSV just got blocked by this network — watch the UI catch it."

Point at the "Data sources" panel showing OSV as unavailable, and the note
that the exploit channel's weight was redistributed rather than silently
dropped.

> "This is the honesty mechanism working as designed — a tool that hides a
> blocked data source and shows you a clean-looking score is worse than one
> that tells you plainly what it couldn't check."
