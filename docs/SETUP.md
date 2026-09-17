# Setup

## Requirements

- Python 3.11 or newer
- Outbound internet access to: `registry.npmjs.org`, `api.osv.dev`,
  `api.deps.dev`, `packages.ecosyste.ms`, `api.github.com` (only if you scan
  a GitHub URL). None require an API key.

## One-command start

```bash
./run.sh
```

This creates a virtualenv in `.venv/` on first run, installs
`requirements.txt`, and starts the server on **http://127.0.0.1:8000**.
Subsequent runs skip straight to starting the server.

## Manual setup

```bash
python3 -m venv .venv
source .venv/bin/activate        # .venv\Scripts\activate on Windows
pip install -r requirements.txt
uvicorn backend.app.main:app --reload --port 8000
```

## Environment variables

Everything is optional. Copy `.env.example` to `.env` and edit, or export
directly. Full reference with defaults lives in `.env.example`; the ones
worth knowing about:

| Variable | Default | What it does |
|---|---|---|
| `GITHUB_TOKEN` | unset | Raises the GitHub API rate limit from 60 to 5,000 req/hr. Only needed if you're scanning several GitHub repos in a row. |
| `ANTHROPIC_API_KEY` | unset | Enables the optional written narration on the package detail panel. Everything else works without it. |
| `RG_OFFLINE` | `false` | Serve every request from the SQLite cache; never touch the network. Useful for a demo on unreliable wifi *after* you've run one scan online to warm the cache. |
| `RG_MAX_PACKAGES` | `400` | Ceiling on packages resolved per scan. Raise for large monorepos — scan time grows roughly linearly. |
| `RG_INCLUDE_DEV` | `true` | Include devDependencies. Deliberately on by default: an install hook in a dev dependency still runs in CI. |

## Running the tests

```bash
pytest
```

38 tests, all synthetic (a hand-built toy dependency graph) or pure-function
(semver parsing, ROC-AUC arithmetic) — no network access required, runs in
well under a second.

## Verifying it's working

```bash
curl http://127.0.0.1:8000/api/health
```

Should return `{"status": "ok", ...}` with a `sources` list. The list is
empty until your first scan — each source's reachability is only checked
when it's actually called.

## Troubleshooting

**A scan reports a source as "unavailable".** Some networks (corporate
proxies, some cloud sandboxes) block one or more of OSV/deps.dev/ecosyste.ms
outright with an HTTP 403. RippleGuard degrades gracefully — the affected
channel's weight is redistributed and the UI states which source failed. It
does not silently produce a clean-looking but wrong result. Check
`docs/DATA_SOURCES.md` for what each source is used for and what happens if
it's missing.

**npm search rate-limits (HTTP 429) during a scan.** Publisher fan-out
lookups are bounded to the 45 most-connected packages / 60 identities
(`MAINTAINER_LOOKUP_PACKAGES` / `MAINTAINER_LOOKUP_BUDGET` in
`graph/builder.py`) specifically to stay under npm's search rate limit on a
typical scan. If you still hit it, lower `RG_CONCURRENCY`.

**A GitHub scan says "No supported manifest found".** RippleGuard looks for
`package.json`, `requirements.txt`, `pom.xml`, `go.mod`, or a lockfile at the
repository root only — it does not currently walk into subdirectories or
monorepo packages.

**The cache file (`rippleguard-cache.sqlite`) grows large.** It's a flat
SQLite response cache; delete it any time to force fresh data. It's already
in `.gitignore`.
