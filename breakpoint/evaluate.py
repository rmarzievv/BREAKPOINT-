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

from dac import Rule, matches  # noqa: E402

__all__ = ["Rule", "load_rule", "load_rules", "matches", "fires_on_any"]


def load_rule(path: Path) -> Rule:
    text = path.read_text(encoding="utf-8")
    return Rule(path=path, raw=yaml.safe_load(text), text=text)


def load_rules(paths: Iterable[Path]) -> list[Rule]:
    return [load_rule(p) for p in sorted(paths)]


def fires_on_any(rule: Rule, events: Iterable[dict]) -> bool:
    """True if the rule matches at least one event (one execution's linked events)."""
    return any(matches(rule, e) for e in events)
