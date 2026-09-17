"""
Optional LLM explanation layer.

Hard rules, enforced in code, not just in the prompt:
  * The model receives ONLY the evidence bundle. It has no tools and no network.
  * Its output is validated: any package name or advisory ID it mentions that is
    not present in the bundle causes the response to be REJECTED and the
    deterministic template returned instead.
  * It never produces a number that feeds back into scoring.

If ANTHROPIC_API_KEY is unset, this module is a no-op and the UI says so.
"""
from __future__ import annotations

import json
import re

import httpx

from ..config import settings

SYSTEM = (
    "You are a supply-chain security analyst writing one short paragraph for a "
    "developer. You will be given a JSON evidence bundle produced by a "
    "deterministic analyser. Explain the risk using ONLY facts present in that "
    "bundle. Never introduce a package name, advisory ID, version, or number "
    "that is not in the bundle. Never speculate about exploitability beyond "
    "what the reachability field states. Do not hedge with disclaimers; the UI "
    "already carries them. 90 words maximum, plain sentences, no bullet points."
)


def available() -> bool:
    return bool(settings.anthropic_api_key)


def _allowed_tokens(bundle: dict) -> set[str]:
    blob = json.dumps(bundle).lower()
    return set(re.findall(r"[a-z0-9@/._-]{3,}", blob))


def _validate(text: str, bundle: dict) -> tuple[bool, str]:
    """Reject any advisory ID or scoped package name that is not in the bundle."""
    allowed = _allowed_tokens(bundle)
    for ident in re.findall(r"\b(?:CVE-\d{4}-\d+|GHSA-[\w-]+)\b", text):
        if ident.lower() not in allowed:
            return False, f"fabricated advisory id: {ident}"
    for pkg in re.findall(r"(@[\w.-]+/[\w.-]+)", text):
        if pkg.lower() not in allowed:
            return False, f"fabricated package name: {pkg}"
    return True, ""


async def explain(bundle: dict) -> dict | None:
    if not available():
        return None
    payload = {
        "model": settings.anthropic_model,
        "max_tokens": 400,
        "system": SYSTEM,
        "messages": [{
            "role": "user",
            "content": "Evidence bundle:\n" + json.dumps(bundle, indent=2),
        }],
    }
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                json=payload,
                headers={
                    "x-api-key": settings.anthropic_api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
            )
        if resp.status_code >= 400:
            return {"ok": False, "error": f"HTTP {resp.status_code}",
                    "detail": resp.text[:300]}
        data = resp.json()
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    text = "".join(b.get("text", "") for b in data.get("content", [])
                   if b.get("type") == "text").strip()
    if not text:
        return {"ok": False, "error": "empty response"}

    valid, reason = _validate(text, bundle)
    if not valid:
        return {"ok": False, "error": "output rejected by grounding check",
                "detail": reason, "rejected_text": text[:400]}
    return {"ok": True, "text": text, "model": settings.anthropic_model,
            "grounding": "validated against evidence bundle"}
