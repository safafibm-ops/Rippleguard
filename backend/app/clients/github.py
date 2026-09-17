"""GitHub client - fetches manifests and first-party source for the import scan."""
from __future__ import annotations

import base64
import re

from ..config import settings
from .base import fetcher

SOURCE = "github"

_REPO_RE = re.compile(
    r"(?:https?://)?(?:www\.)?github\.com/([\w.\-]+)/([\w.\-]+?)(?:\.git)?/?$"
)

MANIFEST_FILES = [
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "requirements.txt", "pyproject.toml", "pom.xml", "go.mod", ".npmrc",
]


def parse_repo_url(url: str) -> tuple[str, str] | None:
    m = _REPO_RE.match((url or "").strip())
    if not m:
        return None
    return m.group(1), m.group(2)


def _headers() -> dict:
    h = {"Accept": "application/vnd.github+json"}
    if settings.github_token:
        h["Authorization"] = f"Bearer {settings.github_token}"
    return h


async def repo_meta(owner: str, repo: str) -> dict | None:
    return await fetcher.get_json(
        SOURCE, f"{settings.github_api}/repos/{owner}/{repo}", headers=_headers()
    )


async def get_file(owner: str, repo: str, path: str, ref: str = "") -> str | None:
    url = f"{settings.github_api}/repos/{owner}/{repo}/contents/{path}"
    if ref:
        url += f"?ref={ref}"
    data = await fetcher.get_json(SOURCE, url, headers=_headers())
    if not isinstance(data, dict) or data.get("encoding") != "base64":
        return None
    try:
        return base64.b64decode(data.get("content", "")).decode("utf-8", "replace")
    except Exception:
        return None


async def list_tree(owner: str, repo: str, ref: str = "HEAD") -> list[str]:
    """Flat file list, used to pick first-party source files for the import scan."""
    url = (f"{settings.github_api}/repos/{owner}/{repo}/git/trees/{ref}"
           f"?recursive=1")
    data = await fetcher.get_json(SOURCE, url, headers=_headers())
    if not isinstance(data, dict):
        return []
    return [t.get("path") for t in (data.get("tree") or [])
            if t.get("type") == "blob" and t.get("path")]
