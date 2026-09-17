"""
Manifest + SBOM ingestion.

Produces a normalised `Project` describing what the application *declares*,
which is different from what it *resolves to*. The trust channel needs both:
the declared range tells you how much drift you accept, the lockfile entry
tells you whether that drift is currently pinned.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict


@dataclass
class Declared:
    """One declared dependency edge from the application."""

    name: str
    spec: str
    ecosystem: str = "npm"
    scope: str = "runtime"          # runtime | dev | optional | peer
    locked_version: str | None = None
    lock_integrity: bool = False    # lockfile entry carries an integrity hash

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class Project:
    name: str = "application"
    version: str = "0.0.0"
    ecosystems: list[str] = field(default_factory=list)
    declared: list[Declared] = field(default_factory=list)
    has_lockfile: bool = False
    lockfile_kind: str = ""
    ignore_scripts: bool = False    # .npmrc ignore-scripts=true
    source_files: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "ecosystems": self.ecosystems,
            "declared": [d.as_dict() for d in self.declared],
            "has_lockfile": self.has_lockfile,
            "lockfile_kind": self.lockfile_kind,
            "ignore_scripts": self.ignore_scripts,
            "source_file_count": len(self.source_files),
            "warnings": self.warnings,
        }


# ---------------------------------------------------------------- npm ------

def parse_package_json(text: str, project: Project, include_dev: bool = True) -> None:
    data = json.loads(text)
    project.name = data.get("name") or project.name
    project.version = data.get("version") or project.version
    if "npm" not in project.ecosystems:
        project.ecosystems.append("npm")
    buckets = [("dependencies", "runtime"), ("optionalDependencies", "optional")]
    if include_dev:
        buckets.append(("devDependencies", "dev"))
    for key, scope in buckets:
        for name, spec in (data.get(key) or {}).items():
            project.declared.append(
                Declared(name=name, spec=str(spec), ecosystem="npm", scope=scope)
            )


def parse_package_lock(text: str, project: Project) -> dict[str, dict]:
    """npm lockfile v1/v2/v3 -> {name: {version, integrity}}.

    Presence of an integrity hash is what earns the floatiness discount.
    """
    data = json.loads(text)
    project.has_lockfile = True
    project.lockfile_kind = f"package-lock v{data.get('lockfileVersion', '?')}"
    resolved: dict[str, dict] = {}

    # v2/v3: "packages": { "node_modules/foo": {...} }
    for path, meta in (data.get("packages") or {}).items():
        if not path or not isinstance(meta, dict):
            continue
        name = meta.get("name") or path.split("node_modules/")[-1]
        if not name:
            continue
        resolved[name] = {
            "version": meta.get("version"),
            "integrity": bool(meta.get("integrity")),
            "dev": bool(meta.get("dev")),
        }
    # v1: "dependencies": { "foo": {version, integrity, dependencies: {...}} }

    def walk(node: dict) -> None:
        for name, meta in (node.get("dependencies") or {}).items():
            if not isinstance(meta, dict):
                continue
            resolved.setdefault(name, {
                "version": meta.get("version"),
                "integrity": bool(meta.get("integrity")),
                "dev": bool(meta.get("dev")),
            })
            walk(meta)

    walk(data)
    return resolved


def parse_yarn_lock(text: str, project: Project) -> dict[str, dict]:
    """Yarn v1 classic lockfile. Enough to recover versions + integrity flags."""
    project.has_lockfile = True
    project.lockfile_kind = "yarn.lock"
    resolved: dict[str, dict] = {}
    current: list[str] = []
    for line in text.splitlines():
        if line and not line.startswith((" ", "\t", "#")):
            current = []
            for entry in line.rstrip(":").split(","):
                entry = entry.strip().strip('"')
                at = entry.rfind("@")
                if at > 0:
                    current.append(entry[:at])
        elif current:
            s = line.strip()
            if s.startswith("version "):
                ver = s.split(" ", 1)[1].strip().strip('"')
                for name in current:
                    resolved.setdefault(name, {"version": ver, "integrity": False,
                                               "dev": False})
            elif s.startswith(("integrity ", "resolved ")):
                for name in current:
                    if name in resolved:
                        resolved[name]["integrity"] = True
    return resolved


def parse_pnpm_lock(text: str, project: Project) -> dict[str, dict]:
    """pnpm-lock.yaml without a YAML dependency: we only need name -> version."""
    project.has_lockfile = True
    project.lockfile_kind = "pnpm-lock.yaml"
    resolved: dict[str, dict] = {}
    for m in re.finditer(r"^\s{2}(/?@?[\w.\-/]+)@([\d][\w.\-+]*):",
                         text, re.MULTILINE):
        name = m.group(1).lstrip("/")
        resolved.setdefault(name, {"version": m.group(2), "integrity": True,
                                   "dev": False})
    return resolved


# --------------------------------------------------------------- python ----

_REQ_RE = re.compile(
    r"^\s*([A-Za-z0-9._\-\[\]]+)\s*((?:[=<>!~]=?[^,;\s]+)(?:\s*,\s*[=<>!~]=?[^,;\s]+)*)?"
)


def parse_requirements(text: str, project: Project) -> None:
    if "pypi" not in project.ecosystems:
        project.ecosystems.append("pypi")
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _REQ_RE.match(line)
        if not m:
            continue
        name = m.group(1).split("[", 1)[0]
        spec = (m.group(2) or "").strip()
        locked = None
        if spec.startswith("==") and "," not in spec:
            locked = spec[2:].strip()
        project.declared.append(
            Declared(name=name, spec=spec or "*", ecosystem="pypi",
                     scope="runtime", locked_version=locked)
        )


# ---------------------------------------------------------------- maven ----

def parse_pom(text: str, project: Project) -> None:
    if "maven" not in project.ecosystems:
        project.ecosystems.append("maven")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        project.warnings.append(f"pom.xml parse failed: {exc}")
        return
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    props = {}
    for p in root.findall(".//m:properties/*", ns) or []:
        tag = p.tag.split("}")[-1]
        props[tag] = (p.text or "").strip()

    def resolve(value: str) -> str:
        m = re.match(r"^\$\{(.+)\}$", value or "")
        return props.get(m.group(1), value) if m else value

    for dep in root.findall(".//m:dependencies/m:dependency", ns):
        gid = dep.findtext("m:groupId", "", ns).strip()
        aid = dep.findtext("m:artifactId", "", ns).strip()
        ver = resolve(dep.findtext("m:version", "", ns).strip())
        scope = dep.findtext("m:scope", "compile", ns).strip()
        if not gid or not aid:
            continue
        project.declared.append(
            Declared(name=f"{gid}:{aid}", spec=ver or "*", ecosystem="maven",
                     scope="dev" if scope == "test" else "runtime",
                     locked_version=ver if re.match(r"^\d", ver or "") else None)
        )


# ----------------------------------------------------------------- SBOM ----

def parse_sbom(text: str, project: Project) -> None:
    """CycloneDX or SPDX JSON. We read PURLs, which carry ecosystem+version."""
    data = json.loads(text)
    project.has_lockfile = True
    components = []
    if data.get("bomFormat") == "CycloneDX" or "components" in data:
        project.lockfile_kind = "CycloneDX SBOM"
        components = data.get("components") or []
        for c in components:
            purl = c.get("purl") or ""
            eco, name, version = _from_purl(purl)
            name = name or c.get("name")
            version = version or c.get("version")
            if not name:
                continue
            project.declared.append(Declared(
                name=name, spec=version or "*", ecosystem=eco or "npm",
                scope="runtime", locked_version=version, lock_integrity=True,
            ))
    elif "packages" in data and "spdxVersion" in data:
        project.lockfile_kind = "SPDX SBOM"
        for p in data.get("packages") or []:
            name, version = p.get("name"), p.get("versionInfo")
            eco = "npm"
            for ref in p.get("externalRefs") or []:
                if ref.get("referenceType") == "purl":
                    e, n, v = _from_purl(ref.get("referenceLocator", ""))
                    eco, name, version = e or eco, n or name, v or version
            if not name:
                continue
            project.declared.append(Declared(
                name=name, spec=version or "*", ecosystem=eco,
                scope="runtime", locked_version=version, lock_integrity=True,
            ))
    else:
        raise ValueError("Unrecognised SBOM format (expected CycloneDX or SPDX JSON)")

    project.ecosystems = sorted({d.ecosystem for d in project.declared}) or ["npm"]
    project.name = (data.get("metadata", {}).get("component", {}).get("name")
                    or data.get("name") or "sbom-project")
    project.warnings.append(
        "SBOM input: every component is treated as pinned, so version-floatiness "
        "cannot be measured. Supply the original manifest for full trust-channel "
        "scoring."
    )


def _from_purl(purl: str) -> tuple[str, str, str]:
    m = re.match(r"^pkg:([^/]+)/(.+?)@([^?#]+)", purl or "")
    if not m:
        m2 = re.match(r"^pkg:([^/]+)/(.+?)(?:[?#]|$)", purl or "")
        if not m2:
            return "", "", ""
        return _norm_eco(m2.group(1)), m2.group(2), ""
    return _norm_eco(m.group(1)), m.group(2), m.group(3)


def _norm_eco(kind: str) -> str:
    return {"npm": "npm", "pypi": "pypi", "maven": "maven", "cargo": "cargo",
            "golang": "go", "nuget": "nuget"}.get(kind.lower(), kind.lower())


# ------------------------------------------------------------- assembly ----

def build_project(files: dict[str, str], include_dev: bool = True) -> Project:
    """files: {relative_path: text}. Returns a normalised Project."""
    project = Project()
    lock: dict[str, dict] = {}

    for path, text in files.items():
        base = path.rsplit("/", 1)[-1]
        try:
            if base == "package.json":
                parse_package_json(text, project, include_dev)
            elif base == "package-lock.json":
                lock.update(parse_package_lock(text, project))
            elif base == "yarn.lock":
                lock.update(parse_yarn_lock(text, project))
            elif base == "pnpm-lock.yaml":
                lock.update(parse_pnpm_lock(text, project))
            elif base.startswith("requirements") and base.endswith(".txt"):
                parse_requirements(text, project)
            elif base == "pom.xml":
                parse_pom(text, project)
            elif base == ".npmrc":
                if re.search(r"^\s*ignore-scripts\s*=\s*true", text,
                             re.MULTILINE | re.IGNORECASE):
                    project.ignore_scripts = True
            elif base.endswith((".cdx.json", ".spdx.json", "bom.json", "sbom.json")):
                parse_sbom(text, project)
        except Exception as exc:
            project.warnings.append(f"{base}: {type(exc).__name__}: {exc}")

    for dep in project.declared:
        entry = lock.get(dep.name)
        if entry and entry.get("version"):
            dep.locked_version = entry["version"]
            dep.lock_integrity = bool(entry.get("integrity"))

    # De-duplicate, preferring runtime scope over dev for the same package.
    seen: dict[tuple[str, str], Declared] = {}
    for dep in project.declared:
        key = (dep.ecosystem, dep.name)
        if key not in seen or (seen[key].scope == "dev" and dep.scope != "dev"):
            seen[key] = dep
    project.declared = list(seen.values())

    if not project.ecosystems:
        project.ecosystems = ["npm"]
    if not project.declared:
        project.warnings.append("No dependencies found in the supplied files.")
    return project
