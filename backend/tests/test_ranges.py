"""Version-range analysis: the input to the trust channel's headline factor."""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.ingest.ranges import (best_match, classify_range, floatiness,
                               parse_version, satisfies)


def test_classify_npm_ranges():
    assert classify_range("1.2.3") == "exact"
    assert classify_range("~1.2.3") == "tilde"
    assert classify_range("^1.2.3") == "caret"
    assert classify_range(">=1.2.3") == "range_op"
    assert classify_range("*") == "wildcard"
    assert classify_range("latest") == "wildcard"
    assert classify_range("git+https://github.com/x/y") == "wildcard"


def test_classify_pypi_ranges():
    assert classify_range("==1.2.3", "pypi") == "exact"
    assert classify_range("~=1.2", "pypi") == "tilde"
    assert classify_range(">=1.0", "pypi") == "range_op"


def test_floatiness_is_ordered():
    """A caret range must always be floatier than a pin. This ordering is the
    core assumption of the trust channel."""
    exact, _, _ = floatiness("1.2.3")
    tilde, _, _ = floatiness("~1.2.3")
    caret, _, _ = floatiness("^1.2.3")
    star, _, _ = floatiness("*")
    assert exact < tilde < caret < star


def test_lockfile_discounts_but_does_not_zero():
    loose, _, _ = floatiness("^1.2.3")
    locked, _, reason = floatiness("^1.2.3", lockfile_pinned=True)
    assert locked < loose
    assert locked > 0, "a lockfile is a discount, never an exemption"
    assert "lockfile" in reason


def test_semver_satisfies():
    assert satisfies("1.3.0", "^1.2.0")
    assert not satisfies("2.0.0", "^1.2.0")
    assert satisfies("1.2.9", "~1.2.0")
    assert not satisfies("1.3.0", "~1.2.0")
    assert satisfies("0.2.1", "^0.2.0")
    assert not satisfies("0.3.0", "^0.2.0"), "caret on 0.x pins the minor"
    assert satisfies("1.5.0", ">=1.0.0 <2.0.0")
    assert satisfies("3.0.0", "^1.0.0 || ^3.0.0")


def test_best_match_picks_highest_satisfying():
    versions = ["1.0.0", "1.2.0", "1.9.3", "2.0.0", "2.1.0-beta.1"]
    assert best_match("^1.0.0", versions) == "1.9.3"
    assert best_match("1.2.0", versions) == "1.2.0"


def test_prerelease_ordering():
    assert parse_version("1.0.0").key() > parse_version("1.0.0-rc.1").key()
