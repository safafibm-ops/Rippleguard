"""Manifest and SBOM ingestion."""
import json, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.ingest.manifest import build_project


def test_package_json_with_lockfile_integrity():
    pkg = json.dumps({"name": "demo", "version": "1.0.0",
                      "dependencies": {"express": "^4.17.1"},
                      "devDependencies": {"nodemon": "~2.0.20"}})
    lock = json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/express": {"version": "4.17.1", "integrity": "sha512-x"},
        "node_modules/nodemon": {"version": "2.0.20", "dev": True}}})
    p = build_project({"package.json": pkg, "package-lock.json": lock})
    assert p.name == "demo" and p.has_lockfile
    express = next(d for d in p.declared if d.name == "express")
    assert express.locked_version == "4.17.1" and express.lock_integrity
    nodemon = next(d for d in p.declared if d.name == "nodemon")
    assert nodemon.scope == "dev" and not nodemon.lock_integrity


def test_npmrc_ignore_scripts_detected():
    pkg = json.dumps({"name": "d", "dependencies": {"a": "^1.0.0"}})
    p = build_project({"package.json": pkg, ".npmrc": "ignore-scripts=true\n"})
    assert p.ignore_scripts is True


def test_requirements_txt():
    p = build_project({"requirements.txt":
                       "Django==4.2.1\nrequests>=2.28\n# comment\nflask\n"})
    names = {d.name: d for d in p.declared}
    assert names["Django"].locked_version == "4.2.1"
    assert names["requests"].spec == ">=2.28"
    assert "flask" in names and "pypi" in p.ecosystems


def test_pom_xml_with_property_substitution():
    pom = """<project xmlns="http://maven.apache.org/POM/4.0.0">
      <properties><jackson.version>2.15.2</jackson.version></properties>
      <dependencies><dependency>
        <groupId>com.fasterxml.jackson.core</groupId>
        <artifactId>jackson-databind</artifactId>
        <version>${jackson.version}</version>
      </dependency></dependencies></project>"""
    p = build_project({"pom.xml": pom})
    d = p.declared[0]
    assert d.name == "com.fasterxml.jackson.core:jackson-databind"
    assert d.spec == "2.15.2"


def test_cyclonedx_sbom():
    sbom = json.dumps({"bomFormat": "CycloneDX", "components": [
        {"name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"}]})
    p = build_project({"bom.json": sbom})
    assert p.declared[0].name == "lodash"
    assert p.declared[0].lock_integrity
    assert any("floatiness cannot be measured" in w for w in p.warnings)


def test_bad_input_is_warned_not_raised():
    p = build_project({"package.json": "{not json"})
    assert p.warnings and not p.declared
