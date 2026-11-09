"""Evaluate arbitrary Sigma rules against events, reusing the detection-as-code evaluator.

detection-as-code is pinned as a git submodule (vendor/detection-as-code). Its
`matches(rule, event)` compiles Sigma to SQL with the pySigma SQLite backend and
runs it on a one-row table. We only build `Rule` objects from any path (e.g. the
pinned SigmaHQ checkout) instead of its own rules/ directory.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterable

import yaml

from . import ROOT

_DAC_SCRIPTS = ROOT / "vendor" / "detection-as-code" / "scripts"
if str(_DAC_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_DAC_SCRIPTS))

import re  # noqa: E402
import sqlite3  # noqa: E402

from dac import Rule, _detection_fields, sqliteBackend  # noqa: E402

__all__ = ["Rule", "load_rule", "load_rules", "matches", "fires_on_any"]


def _regexp(pattern: str, value: str | None) -> bool:
    return value is not None and re.search(pattern, value) is not None


def matches(rule: Rule, event: dict) -> bool:
    """Same as dac.matches, plus a REGEXP function (SigmaHQ rules use |re; dac's own rules never did).

    Candidate upstream fix for detection-as-code.
    """
    query = sqliteBackend().convert(rule.collection())[0]
    columns = set(event) | _detection_fields(rule.raw["detection"])
    db = sqlite3.connect(":memory:")
    db.create_function("REGEXP", 2, _regexp, deterministic=True)
    db.execute(f"CREATE TABLE logs ({', '.join(f'\"{c}\" TEXT' for c in sorted(columns))})")
    db.execute(f"INSERT INTO logs ({', '.join(f'\"{c}\"' for c in event)}) VALUES ({', '.join('?' for _ in event)})",
               [str(v) for v in event.values()])
    return db.execute(query).fetchone() is not None


def load_rule(path: Path) -> Rule:
    text = path.read_text(encoding="utf-8")
    return Rule(path=path, raw=yaml.safe_load(text), text=text)


def load_rules(paths: Iterable[Path]) -> list[Rule]:
    return [load_rule(p) for p in sorted(paths)]


def fires_on_any(rule: Rule, events: Iterable[dict]) -> bool:
    """True if the rule matches at least one event (one execution's linked events)."""
    return any(matches(rule, e) for e in events)
