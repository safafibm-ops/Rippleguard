"""
Central configuration for RippleGuard.

Every scoring weight lives here, as a plain constant, on purpose. The whole
pitch of this project is that the risk arithmetic is inspectable, so the
weights must not be buried inside the scoring functions. The API exposes this
table at GET /api/model so the UI can render the exact formula being used.

NONE OF THESE WEIGHTS ARE EMPIRICALLY CALIBRATED. They are prototype
heuristics. See docs/RISK_MODEL.md and the evaluation harness in
app/evaluation/ for how we test whether the ranking they produce is better
than a CVSS-only ranking against real incident data.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures"
FRONTEND = ROOT / "frontend"


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class TrustWeights:
    """Trust channel = 'an attacker publishes a malicious version'.

    This channel does NOT care whether your code calls the package. A malicious
    preinstall/postinstall hook runs during `npm install` regardless of
    reachability. That is the whole reason this channel exists separately.
    """

    # Would a malicious publish reach your build automatically? Driven by the
    # declared version range and whether a lockfile with integrity hashes pins it.
    version_floatiness: float = 0.34
    # Does this package execute code at install time (preinstall/install/postinstall)?
    install_hook: float = 0.26
    # How many other packages does the smallest set of publishers for this
    # package also control? One phished account -> that many packages.
    maintainer_fanout: float = 0.16
    # How recently was this version published? Newly published versions sit
    # inside the detection window where a malicious publish is not yet flagged.
    publish_recency: float = 0.10
    # Structural amplification inside the scanned application.
    downstream_reach: float = 0.14

    def total(self) -> float:
        return (
            self.version_floatiness
            + self.install_hook
            + self.maintainer_fanout
            + self.publish_recency
            + self.downstream_reach
        )


@dataclass(frozen=True)
class ExploitWeights:
    """Exploit channel = 'an attacker exploits a known CVE'.

    This is the channel every commercial SCA tool already scores. We keep it
    so we can show where the two channels disagree.
    """

    severity: float = 0.55        # normalised CVSS / OSV severity
    reachability: float = 0.30    # import-level proxy, NOT function-level
    exposure_depth: float = 0.15  # direct dependencies are easier to reach

    def total(self) -> float:
        return self.severity + self.reachability + self.exposure_depth


@dataclass(frozen=True)
class BlendWeights:
    """How the two channels and structural criticality combine into one number."""

    exploit: float = 0.40
    trust: float = 0.40
    structural: float = 0.20

    def total(self) -> float:
        return self.exploit + self.trust + self.structural


@dataclass(frozen=True)
class FloatinessTable:
    """Maps a declared version range to an inheritance factor in [0, 1].

    'If a malicious version of this package were published in the next hour,
    would my next install pick it up without anyone approving it?'
    """

    exact: float = 0.02          # "1.2.3"
    tilde: float = 0.45          # "~1.2.3"  -> patch drift
    caret: float = 0.80          # "^1.2.3"  -> minor drift, the npm default
    range_op: float = 0.85       # ">=1.2.3", "1.x"
    wildcard: float = 1.00       # "*", "latest", "", git/http refs
    unknown: float = 0.60

    # A lockfile with integrity hashes does not eliminate the risk (a range
    # bump, a fresh `npm install`, or a dependabot PR re-resolves it) but it
    # does mean `npm ci` is reproducible. Multiplicative discount.
    lockfile_discount: float = 0.30
    # `ignore-scripts=true` in .npmrc neutralises the install-hook path.
    ignore_scripts_hook_factor: float = 0.05
    # A package with no install hooks still runs code when imported at runtime.
    no_hook_residual: float = 0.30


@dataclass(frozen=True)
class Settings:
    # --- data sources -------------------------------------------------------
    osv_api: str = os.environ.get("RG_OSV_API", "https://api.osv.dev")
    depsdev_api: str = os.environ.get("RG_DEPSDEV_API", "https://api.deps.dev")
    ecosystems_api: str = os.environ.get(
        "RG_ECOSYSTEMS_API", "https://packages.ecosyste.ms/api/v1"
    )
    npm_registry: str = os.environ.get("RG_NPM_REGISTRY", "https://registry.npmjs.org")
    pypi_api: str = os.environ.get("RG_PYPI_API", "https://pypi.org/pypi")
    github_api: str = os.environ.get("RG_GITHUB_API", "https://api.github.com")
    github_token: str = os.environ.get("GITHUB_TOKEN", "")

    # --- LLM (optional, explanation only) -----------------------------------
    anthropic_api_key: str = os.environ.get("ANTHROPIC_API_KEY", "")
    anthropic_model: str = os.environ.get("RG_LLM_MODEL", "claude-sonnet-4-6")

    # --- behaviour ----------------------------------------------------------
    offline: bool = _env_bool("RG_OFFLINE", False)
    cache_path: str = os.environ.get("RG_CACHE", str(ROOT / "rippleguard-cache.sqlite"))
    cache_ttl_seconds: int = _env_int("RG_CACHE_TTL", 60 * 60 * 12)
    http_timeout: int = _env_int("RG_HTTP_TIMEOUT", 20)
    max_concurrency: int = _env_int("RG_CONCURRENCY", 12)
    max_packages: int = _env_int("RG_MAX_PACKAGES", 400)
    max_depth: int = _env_int("RG_MAX_DEPTH", 6)
    include_dev_dependencies: bool = _env_bool("RG_INCLUDE_DEV", True)

    trust: TrustWeights = field(default_factory=TrustWeights)
    exploit: ExploitWeights = field(default_factory=ExploitWeights)
    blend: BlendWeights = field(default_factory=BlendWeights)
    floatiness: FloatinessTable = field(default_factory=FloatinessTable)

    def model_card(self) -> dict:
        """Everything the UI needs to render the formula, verbatim."""
        return {
            "trust_channel_weights": asdict(self.trust),
            "exploit_channel_weights": asdict(self.exploit),
            "blend_weights": asdict(self.blend),
            "floatiness_table": asdict(self.floatiness),
            "calibrated": False,
            "disclaimer": (
                "These weights are prototype heuristics. They have not been fitted "
                "to data. Scores are labelled 'exposure', never 'probability'."
            ),
        }


settings = Settings()
