"""Import-graph reachability proxy."""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.reachability.imports import (STATE_IMPORTED, STATE_PRESENT,
                                      classify, extract_imports)

JS = """
const express = require('express');
import _ from 'lodash';
import { get } from 'lodash/fp';
import cfg from './local-config';
const scoped = require('@scope/thing/sub');
"""


def test_extract_js_imports_and_scopes():
    found = extract_imports({"src/app.js": JS})
    assert {"express", "lodash", "@scope/thing"} <= found
    assert "./local-config" not in found, "relative paths are not packages"


def test_python_imports():
    found = extract_imports({"main.py": "import requests\nfrom django.db import models\n"})
    assert {"requests", "django"} <= found


def test_node_modules_is_not_first_party():
    found = extract_imports({"node_modules/x/index.js": "require('evil')"})
    assert found == set()


def test_classify_states():
    files = {"src/app.js": JS}
    imported = extract_imports(files)
    assert classify("lodash", imported, files)["state"] == STATE_IMPORTED
    unused = classify("left-pad", imported, files)
    assert unused["state"] == STATE_PRESENT
    assert unused["weight"] < classify("lodash", imported, files)["weight"]
