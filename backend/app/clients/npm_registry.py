"""
npm registry client.

The registry is the only source that gives us the three trust-channel signals
that matter and that nothing else exposes together:

  * `scripts.preinstall/install/postinstall` on the *resolved version*
    -> does this package execute code during `npm install`?
  * `maintainers` -> which publishing identities can push a new version?
  * `time` -> when was this version published? (detection-window proxy)

It also doubles as our fallback dependency resolver when deps.dev is not
reachable, which is why we keep the full packument.
"""
from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import quote

from ..config import settings
from ..ingest.ranges import best_match
from .base import fetcher

SOURCE = "npm-registry"

# Abbreviated packument: same data, an order of magnitude less bandwidth.
_ACCEPT = {"Accept": "application/vnd.npm.install-v1+json"}

_packument_cache: dict[str, Any] = {}
_full_cache: dict[str, Any] = {}


def _encode(name: str) -> str:
    # Scoped packages: @scope/name -> @scope%2Fname
    return quote(name, safe="@")


async def packument(name: str) -> dict | None:
    """Abbreviated packument (versions + dist + dependencies + bin)."""
    if name in _packument_cache:
        return _packument_cache[name]
    data = await fetcher.get_json(
        SOURCE, f"{settings.npm_registry}/{_encode(name)}", headers=_ACCEPT
    )
    _packument_cache[name] = data
    return data


async def full_packument(name: str) -> dict | None:
    """Full document - needed for `maintainers`, which the abbreviated form omits."""
    if name in _full_cache:
        return _full_cache[name]
    data = await fetcher.get_json(SOURCE, f"{settings.npm_registry}/{_encode(name)}")
    _full_cache[name] = data
    return data


async def resolve_version(name: str, spec: str | None) -> str | None:
    doc = await packument(name)
    if not doc:
        return None
    dist_tags = doc.get("dist-tags") or {}
    if spec in dist_tags:
        return dist_tags[spec]
    versions = list((doc.get("versions") or {}).keys())
    if not versions:
        return dist_tags.get("latest")
    return best_match(spec, versions)


async def version_metadata(name: str, version: str) -> dict:
    """Trust-channel facts about one resolved package version.

    Returns a dict with keys that are always present, so downstream scoring
    never has to guess whether a lookup succeeded - it checks `available`.
    """
    out: dict[str, Any] = {
        "available": False,
        "install_scripts": [],
        "has_install_hook": False,
        "maintainers": [],
        "maintainer_count": 0,
        "published_at": None,
        "deprecated": False,
        "dependencies": {},
        "latest_version": None,
        "all_versions": [],
    }
    abbrev = await packument(name)
    if not abbrev:
        return out

    out["available"] = True
    versions = abbrev.get("versions") or {}
    out["all_versions"] = list(versions.keys())
    out["latest_version"] = (abbrev.get("dist-tags") or {}).get("latest")
    vdoc = versions.get(version) or {}
    out["dependencies"] = dict(vdoc.get("dependencies") or {})
    out["deprecated"] = bool(vdoc.get("deprecated"))

    scripts = vdoc.get("scripts") or {}
    # The abbreviated packument sets `hasInstallScript` instead of inlining
    # scripts; honour both so we work against mirrors too.
    hooks = [k for k in ("preinstall", "install", "postinstall") if k in scripts]
    if vdoc.get("hasInstallScript"):
        out["has_install_hook"] = True
        if not hooks:
            hooks = ["(install script declared; body not in abbreviated packument)"]
    out["install_scripts"] = hooks
    out["has_install_hook"] = bool(hooks) or bool(vdoc.get("hasInstallScript"))

    full = await full_packument(name)
    if full:
        maints = full.get("maintainers") or []
        names = [m.get("name") for m in maints if isinstance(m, dict) and m.get("name")]
        out["maintainers"] = names
        out["maintainer_count"] = len(names)
        out["published_at"] = (full.get("time") or {}).get(version)
        vfull = (full.get("versions") or {}).get(version) or {}
        fscripts = vfull.get("scripts") or {}
        fhooks = [k for k in ("preinstall", "install", "postinstall") if k in fscripts]
        if fhooks:
            out["install_scripts"] = fhooks
            out["has_install_hook"] = True
        if not out["dependencies"]:
            out["dependencies"] = dict(vfull.get("dependencies") or {})
    return out


async def maintainer_package_count(username: str) -> int | None:
    """How many packages can this publishing identity push to?

    This is maintainer fan-out: the blast radius of one phished account.
    npm's search endpoint reports a total for `maintainer:<user>`.
    """
    url = (
        f"{settings.npm_registry}/-/v1/search"
        f"?text=maintainer:{quote(username)}&size=1"
    )
    data = await fetcher.get_json(SOURCE, url)
    if not isinstance(data, dict):
        return None
    total = data.get("total")
    return int(total) if isinstance(total, int) else None


async def bulk_maintainer_counts(usernames: list[str]) -> dict[str, int]:
    uniq = sorted({u for u in usernames if u})
    results = await asyncio.gather(
        *(maintainer_package_count(u) for u in uniq), return_exceptions=True
    )
    out: dict[str, int] = {}
    for user, res in zip(uniq, results):
        if isinstance(res, int):
            out[user] = res
    return out
