"""
ecosyste.ms client.

This is the source most teams miss. deps.dev gives dependent *counts*;
ecosyste.ms gives the actual *list* of dependent packages and repositories,
free, 5,000 requests/hour, no API key. That list is what makes a forward
propagation simulation across the public ecosystem possible at all - without
it you can only walk downward from your own app.
"""
from __future__ import annotations

from urllib.parse import quote

from ..config import settings
from .base import fetcher

SOURCE = "ecosyste.ms"

_REGISTRY = {"npm": "npmjs.org", "pypi": "pypi.org", "maven": "repo1.maven.org",
             "cargo": "crates.io", "go": "proxy.golang.org", "nuget": "nuget.org"}


def _base(eco: str, name: str) -> str:
    return (f"{settings.ecosystems_api}/registries/{_REGISTRY.get(eco, 'npmjs.org')}"
            f"/packages/{quote(name, safe='')}")


async def package_info(eco: str, name: str) -> dict | None:
    return await fetcher.get_json(SOURCE, _base(eco, name))


async def dependent_packages(eco: str, name: str, limit: int = 40) -> list[dict]:
    """Actual downstream package list - the forward edges of the ecosystem."""
    url = f"{_base(eco, name)}/dependent_packages?per_page={min(limit, 100)}"
    data = await fetcher.get_json(SOURCE, url)
    if not isinstance(data, list):
        return []
    out = []
    for item in data[:limit]:
        if not isinstance(item, dict):
            continue
        out.append({
            "name": item.get("name"),
            "ecosystem": eco,
            "downloads": item.get("downloads") or 0,
            "dependent_packages_count": item.get("dependent_packages_count") or 0,
            "dependent_repos_count": item.get("dependent_repos_count") or 0,
            "latest_release_published_at": item.get("latest_release_published_at"),
        })
    return out


def reach_signals(info: dict | None) -> dict:
    """Normalise the popularity signals we actually use in scoring."""
    if not isinstance(info, dict):
        return {"available": False, "dependent_packages": 0,
                "dependent_repos": 0, "downloads": 0, "maintainers": 0}
    return {
        "available": True,
        "dependent_packages": int(info.get("dependent_packages_count") or 0),
        "dependent_repos": int(info.get("dependent_repos_count") or 0),
        "downloads": int(info.get("downloads") or 0),
        "maintainers": int(info.get("maintainers_count") or 0),
    }
