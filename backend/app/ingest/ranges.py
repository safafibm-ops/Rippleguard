"""
Version range analysis.

This module is the heart of the trust channel and the single most novel
measurable in RippleGuard: **inheritance exposure**.

The question it answers is not "am I vulnerable?" but:

    "If a malicious version of this package were published right now, would my
     next install pick it up without a human approving it?"

That is a property of the *declared range* plus the lockfile state, and it is
directly computable from a manifest. It is what actually determined who got hit
by the npm worm campaigns of 2025-2026, and almost no tool scores it.

We also implement just enough semver to resolve ranges against a registry's
version list, because deps.dev is not always reachable and we need a fallback
resolver that works from the npm registry alone.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..config import settings

_SEMVER_RE = re.compile(
    r"^\s*v?(\d+)\.(\d+)\.(\d+)"
    r"(?:-([0-9A-Za-z.\-]+))?"
    r"(?:\+([0-9A-Za-z.\-]+))?\s*$"
)


@dataclass(frozen=True, order=False)
class Version:
    major: int
    minor: int
    patch: int
    prerelease: tuple = ()

    @property
    def is_prerelease(self) -> bool:
        return bool(self.prerelease)

    def key(self):
        # Releases sort above prereleases (npm/semver rule).
        return (self.major, self.minor, self.patch, 1 if not self.prerelease else 0,
                self.prerelease)

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        return base + ("-" + ".".join(str(p) for p in self.prerelease)
                       if self.prerelease else "")


def parse_version(raw: str | None) -> Version | None:
    if not raw:
        return None
    m = _SEMVER_RE.match(str(raw))
    if not m:
        return None
    major, minor, patch, pre, _build = m.groups()
    prerelease: tuple = ()
    if pre:
        parts = []
        for chunk in pre.split("."):
            parts.append((0, int(chunk)) if chunk.isdigit() else (1, chunk))
        prerelease = tuple(parts)
    return Version(int(major), int(minor), int(patch), prerelease)


# --------------------------------------------------------------------------
# Range classification -> floatiness
# --------------------------------------------------------------------------

RANGE_KIND_EXACT = "exact"
RANGE_KIND_TILDE = "tilde"
RANGE_KIND_CARET = "caret"
RANGE_KIND_RANGE = "range_op"
RANGE_KIND_WILDCARD = "wildcard"
RANGE_KIND_UNKNOWN = "unknown"

_KIND_LABEL = {
    RANGE_KIND_EXACT: "pinned to one version",
    RANGE_KIND_TILDE: "floats on patch releases",
    RANGE_KIND_CARET: "floats on minor releases",
    RANGE_KIND_RANGE: "open comparator range",
    RANGE_KIND_WILDCARD: "accepts any published version",
    RANGE_KIND_UNKNOWN: "unrecognised specifier",
}


def classify_range(spec: str | None, ecosystem: str = "npm") -> str:
    """Bucket a declared dependency specifier by how much it lets drift in."""
    if spec is None:
        return RANGE_KIND_UNKNOWN
    s = str(spec).strip()
    if s == "" or s in {"*", "x", "X", "latest", "next"}:
        return RANGE_KIND_WILDCARD
    if s.startswith(("git+", "git:", "http://", "https://", "file:", "link:", "npm:")):
        # A git/tarball reference tracking a branch is maximally floaty.
        return RANGE_KIND_WILDCARD if "#" not in s else RANGE_KIND_RANGE

    if ecosystem == "pypi":
        if s.startswith("=="):
            return RANGE_KIND_EXACT
        if s.startswith("~="):
            return RANGE_KIND_TILDE
        if s.startswith((">=", ">", "<", "<=", "!=")):
            return RANGE_KIND_RANGE
        return RANGE_KIND_UNKNOWN

    if s.startswith("^"):
        return RANGE_KIND_CARET
    if s.startswith("~"):
        return RANGE_KIND_TILDE
    if s.startswith((">", "<", "=")) or "||" in s or " - " in s:
        return RANGE_KIND_RANGE
    if re.match(r"^\d+\.\d+\.\d+", s) and not re.search(r"[*x]", s):
        return RANGE_KIND_EXACT
    if re.match(r"^\d+(\.\d+)?(\.[xX*])?$", s) or re.search(r"[*xX]", s):
        return RANGE_KIND_RANGE
    return RANGE_KIND_UNKNOWN


def floatiness(
    spec: str | None,
    *,
    ecosystem: str = "npm",
    lockfile_pinned: bool = False,
) -> tuple[float, str, str]:
    """Return (factor in [0,1], range_kind, human explanation).

    `lockfile_pinned` means a lockfile entry with an integrity hash exists for
    this exact resolution. That earns a discount, not an exemption: a lockfile
    makes `npm ci` reproducible, but a range bump, a fresh `npm install`, or an
    auto-merged bot PR re-resolves the range and picks up the new publish.
    """
    table = settings.floatiness
    kind = classify_range(spec, ecosystem)
    base = getattr(table, kind if kind != "range_op" else "range_op")
    reason = _KIND_LABEL[kind]
    factor = base
    if lockfile_pinned:
        factor = base * table.lockfile_discount
        reason += "; lockfile with integrity hash present"
    return round(min(1.0, max(0.0, factor)), 4), kind, reason


# --------------------------------------------------------------------------
# Minimal range satisfaction, used by the npm-registry fallback resolver
# --------------------------------------------------------------------------

def _caret_bounds(v: Version) -> tuple[Version, Version]:
    if v.major > 0:
        return v, Version(v.major + 1, 0, 0)
    if v.minor > 0:
        return v, Version(0, v.minor + 1, 0)
    return v, Version(0, 0, v.patch + 1)


def _tilde_bounds(v: Version) -> tuple[Version, Version]:
    return v, Version(v.major, v.minor + 1, 0)


def _satisfies_single(version: Version, comparator: str) -> bool:
    c = comparator.strip()
    if c in {"", "*", "x", "X", "latest"}:
        return not version.is_prerelease
    if c.startswith("^"):
        base = parse_version(c[1:])
        if not base:
            return False
        lo, hi = _caret_bounds(base)
        return lo.key() <= version.key() < hi.key()
    if c.startswith("~"):
        base = parse_version(c[1:])
        if not base:
            return False
        lo, hi = _tilde_bounds(base)
        return lo.key() <= version.key() < hi.key()
    for op in (">=", "<=", ">", "<", "=="):
        if c.startswith(op):
            base = parse_version(c[len(op):])
            if not base:
                return False
            a, b = version.key(), base.key()
            return {
                ">=": a >= b, "<=": a <= b, ">": a > b, "<": a < b, "==": a == b
            }[op]
    if c.startswith("="):
        base = parse_version(c[1:])
        return bool(base) and version.key() == base.key()
    # bare partial like "1" or "1.2"
    m = re.match(r"^(\d+)(?:\.(\d+))?(?:\.([\dxX*]+))?$", c)
    if m:
        major, minor, patch = m.groups()
        if minor is None:
            return version.major == int(major)
        if patch is None or patch in {"x", "X", "*"}:
            return version.major == int(major) and version.minor == int(minor)
        return version.key()[:3] == (int(major), int(minor), int(patch))
    base = parse_version(c)
    return bool(base) and version.key() == base.key()


def satisfies(version_str: str, spec: str | None) -> bool:
    v = parse_version(version_str)
    if v is None:
        return False
    if spec is None or str(spec).strip() in {"", "*", "latest", "x"}:
        return not v.is_prerelease
    spec = str(spec).strip()
    for alternative in spec.split("||"):
        alternative = alternative.strip()
        if " - " in alternative:  # hyphen range "1.2.3 - 2.0.0"
            lo_s, hi_s = alternative.split(" - ", 1)
            lo, hi = parse_version(lo_s), parse_version(hi_s)
            if lo and hi and lo.key() <= v.key() <= hi.key():
                return True
            continue
        parts = [p for p in re.split(r"\s+", alternative) if p]
        if parts and all(_satisfies_single(v, p) for p in parts):
            return True
    return False


def best_match(spec: str | None, candidates: list[str]) -> str | None:
    """Highest published version satisfying `spec`, npm-style."""
    matching = [c for c in candidates if satisfies(c, spec)]
    if not matching:
        # Fall back to highest stable release so the graph stays connected.
        stable = [c for c in candidates
                  if (pv := parse_version(c)) and not pv.is_prerelease]
        pool = stable or candidates
        if not pool:
            return None
        return max(pool, key=lambda c: parse_version(c).key())
    return max(matching, key=lambda c: parse_version(c).key())
