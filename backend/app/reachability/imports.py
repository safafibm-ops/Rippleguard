"""
Import-level reachability proxy.

DELIBERATE SCOPE LIMIT. This is NOT function-level reachability. Endor Labs
and OSV-Scanner do function-level call-graph analysis; replicating that needs a
CVE-to-vulnerable-function database we do not have and cannot build in a
hackathon. Overclaiming here would be the fastest way to lose credibility.

What we actually do: parse the application's own source files and extract the
set of package names it imports. That lets us separate three states that most
free tools collapse into one:

    PRESENT            in the dependency tree, never imported by first-party code
    IMPORTED           first-party code imports the package
    SYMBOL_REFERENCED  first-party code imports it AND references an identifier
                       named in the advisory summary

Every finding carries `method: "import-graph proxy"` so the UI can say exactly
what evidence backs the label.

Note for the trust channel: reachability is deliberately NOT applied there. An
install hook executes during `npm install` whether or not you ever import the
package, so gating trust-channel risk on reachability would be wrong - it is
exactly the mistake that makes reachability-first prioritisation blind to the
2025-2026 worm campaigns.
"""
from __future__ import annotations

import re

STATE_PRESENT = "PRESENT"
STATE_IMPORTED = "IMPORTED"
STATE_SYMBOL = "SYMBOL_REFERENCED"

STATE_WEIGHT = {STATE_PRESENT: 0.25, STATE_IMPORTED: 0.70, STATE_SYMBOL: 1.00}

STATE_EXPLANATION = {
    STATE_PRESENT: "present in the dependency tree but not imported by first-party code",
    STATE_IMPORTED: "imported by first-party code",
    STATE_SYMBOL: "imported by first-party code, and an identifier named in the advisory appears in that code",
}

SOURCE_EXTENSIONS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py")

_JS_PATTERNS = [
    re.compile(r"""require\(\s*['"]([^'"]+)['"]\s*\)"""),
    re.compile(r"""import\s+[^'"]*?from\s*['"]([^'"]+)['"]"""),
    re.compile(r"""import\s*\(\s*['"]([^'"]+)['"]\s*\)"""),
    re.compile(r"""import\s*['"]([^'"]+)['"]"""),
    re.compile(r"""export\s+[^'"]*?from\s*['"]([^'"]+)['"]"""),
]
_PY_PATTERNS = [
    re.compile(r"^\s*import\s+([A-Za-z0-9_.]+)", re.MULTILINE),
    re.compile(r"^\s*from\s+([A-Za-z0-9_.]+)\s+import", re.MULTILINE),
]

_SKIP_DIRS = ("node_modules/", "dist/", "build/", "vendor/", ".git/",
              "site-packages/", "coverage/", "__pycache__/")


def is_first_party(path: str) -> bool:
    p = path.lower()
    return p.endswith(SOURCE_EXTENSIONS) and not any(d in p for d in _SKIP_DIRS)


def _npm_root(specifier: str) -> str | None:
    """'lodash/fp/get' -> 'lodash'; '@scope/pkg/x' -> '@scope/pkg'."""
    if not specifier or specifier.startswith((".", "/", "node:")):
        return None
    parts = specifier.split("/")
    if specifier.startswith("@"):
        return "/".join(parts[:2]) if len(parts) >= 2 else None
    return parts[0]


def extract_imports(files: dict[str, str]) -> set[str]:
    """Package names imported anywhere in the supplied first-party sources."""
    found: set[str] = set()
    for path, text in files.items():
        if not is_first_party(path):
            continue
        patterns = _PY_PATTERNS if path.endswith(".py") else _JS_PATTERNS
        for pat in patterns:
            for m in pat.finditer(text):
                spec = m.group(1)
                root = spec.split(".")[0] if path.endswith(".py") else _npm_root(spec)
                if root:
                    found.add(root)
    return found


_IDENT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{3,})\b")
_ADVISORY_STOPWORDS = {
    "the", "and", "that", "this", "with", "from", "into", "when", "which",
    "have", "been", "before", "after", "allows", "attacker", "remote", "user",
    "input", "package", "versions", "version", "prior", "affected", "vulnerable",
    "vulnerability", "denial", "service", "arbitrary", "could", "occur", "code",
    "execution", "issue", "fixed", "patch", "https", "github", "commit", "npm",
}


def advisory_identifiers(summary: str) -> set[str]:
    """Candidate function/identifier names mentioned in an advisory summary.

    Crude on purpose: an advisory that names `lodash.template` gives us a token
    to grep for. If nothing plausible is found we simply never reach the
    SYMBOL_REFERENCED state, which fails safe (downward).
    """
    out = set()
    for m in _IDENT_RE.finditer(summary or ""):
        tok = m.group(1)
        if tok.lower() in _ADVISORY_STOPWORDS:
            continue
        # Identifier-looking tokens: camelCase, snake_case, or dotted method refs
        if re.search(r"[a-z][A-Z]", tok) or "_" in tok:
            out.add(tok)
    return out


def classify(
    package_name: str,
    imported: set[str],
    source_files: dict[str, str],
    advisory_summaries: list[str] | None = None,
) -> dict:
    """Return the reachability record for one package."""
    if package_name not in imported:
        return {
            "state": STATE_PRESENT,
            "weight": STATE_WEIGHT[STATE_PRESENT],
            "method": "import-graph proxy",
            "explanation": STATE_EXPLANATION[STATE_PRESENT],
            "evidence": [],
        }

    evidence = []
    for path, text in source_files.items():
        if not is_first_party(path):
            continue
        if re.search(re.escape(package_name), text):
            evidence.append(path)
        if len(evidence) >= 4:
            break

    state = STATE_IMPORTED
    symbols: list[str] = []
    for summary in advisory_summaries or []:
        for ident in advisory_identifiers(summary):
            for path, text in source_files.items():
                if is_first_party(path) and re.search(rf"\b{re.escape(ident)}\b", text):
                    symbols.append(ident)
                    state = STATE_SYMBOL
                    break
            if state == STATE_SYMBOL:
                break

    return {
        "state": state,
        "weight": STATE_WEIGHT[state],
        "method": "import-graph proxy",
        "explanation": STATE_EXPLANATION[state],
        "evidence": evidence[:4],
        "matched_symbols": sorted(set(symbols))[:3],
    }


DISCLAIMER = (
    "Reachability here is an import-graph proxy, not function-level call-graph "
    "analysis. It answers 'does first-party code import this package', not "
    "'does first-party code call the vulnerable function'. It over-reports "
    "relative to a tool with a CVE-to-function database."
)
