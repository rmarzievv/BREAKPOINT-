"""Oracle checks: did the implementation achieve its effect?

Each implementation in implementations.yaml lists `success` checks. All must pass
for `success`. A Defender/ASR event in the execution window gives `blocked`.
Anything else is `fail`. See ORACLES.md.

Checks are pure functions of (Execution, Context) so they can be unit-tested
off Windows. Checks that need the live system (registry, follow-up commands)
go through `ctx.run`, which the harness provides.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Callable

SUCCESS, FAIL, BLOCKED = "success", "fail", "blocked"


@dataclass
class Execution:
    exit_code: int | None
    stdout: str
    stderr: str = ""
    start_utc: str = ""
    end_utc: str = ""
    pid: int | None = None


@dataclass
class Context:
    """Known true values and live-system access, filled by the harness."""
    known: dict[str, str] = field(default_factory=dict)       # e.g. computername, lab_build, gateway_ip
    run: Callable[[str, str], Execution] | None = None       # run(shell, command) -> Execution
    defender_events: Callable[[str, str], list[dict]] | None = None  # (start, end) -> events

    def expand(self, text: str) -> str:
        """Replace {name} placeholders with known values."""
        return re.sub(r"\{(\w+)\}", lambda m: self.known.get(m.group(1), m.group(0)), text)


# ---- individual checks -------------------------------------------------------
# Each takes (execution, ctx, arg) and returns (passed, detail).

def _exit_code(ex: Execution, ctx: Context, arg) -> tuple[bool, str]:
    return ex.exit_code == int(arg), f"exit_code={ex.exit_code}"


def _contains(ex: Execution, ctx: Context, arg) -> tuple[bool, str]:
    needle = ctx.expand(str(arg))
    return needle.lower() in ex.stdout.lower(), f"contains {needle!r}"


def _regex(ex: Execution, ctx: Context, arg) -> tuple[bool, str]:
    pattern = ctx.expand(str(arg))
    return re.search(pattern, ex.stdout, re.IGNORECASE | re.MULTILINE) is not None, f"regex {pattern!r}"


def _stdout_equals(ex: Execution, ctx: Context, arg) -> tuple[bool, str]:
    want = ctx.expand(str(arg)).strip()
    return ex.stdout.strip() == want, f"stdout == {want!r}"


def _regex_group_equals(ex: Execution, ctx: Context, arg) -> tuple[bool, str]:
    """arg: {pattern: '...(?P<v>...)...', equals: '{lab_build}'}"""
    m = re.search(ctx.expand(arg["pattern"]), ex.stdout, re.IGNORECASE | re.MULTILINE)
    want = ctx.expand(str(arg["equals"]))
    got = m.group("v") if m else None
    return got == want, f"captured {got!r} == {want!r}"


def _public_ipv4(ex: Execution, ctx: Context, arg) -> tuple[bool, str]:
    text = ex.stdout.strip()
    try:
        ip = ipaddress.IPv4Address(text)
    except ValueError:
        return False, f"not an IPv4: {text[:40]!r}"
    return ip.is_global, f"{ip} global={ip.is_global}"


def _command_succeeds(ex: Execution, ctx: Context, arg) -> tuple[bool, str]:
    """arg: {shell: cmd|powershell, command: '...'} -> follow-up exit code 0."""
    if ctx.run is None:
        return False, "no live runner"
    follow = ctx.run(arg.get("shell", "cmd"), ctx.expand(arg["command"]))
    return follow.exit_code == 0, f"follow-up exit_code={follow.exit_code}"


def _command_fails(ex: Execution, ctx: Context, arg) -> tuple[bool, str]:
    ok, detail = _command_succeeds(ex, ctx, arg)
    return (not ok) and ctx.run is not None, detail


def _command_stdout_contains(ex: Execution, ctx: Context, arg) -> tuple[bool, str]:
    """arg: {shell, command, contains}"""
    if ctx.run is None:
        return False, "no live runner"
    follow = ctx.run(arg.get("shell", "cmd"), ctx.expand(arg["command"]))
    needle = ctx.expand(str(arg["contains"]))
    return follow.exit_code == 0 and needle.lower() in follow.stdout.lower(), f"follow-up contains {needle!r}"


CHECKS: dict[str, Callable[[Execution, Context, object], tuple[bool, str]]] = {
    "exit_code": _exit_code,
    "contains": _contains,
    "regex": _regex,
    "stdout_equals": _stdout_equals,
    "regex_group_equals": _regex_group_equals,
    "public_ipv4": _public_ipv4,
    "command_succeeds": _command_succeeds,
    "command_fails": _command_fails,
    "command_stdout_contains": _command_stdout_contains,
}


def evaluate(checks: list[dict], ex: Execution, ctx: Context) -> tuple[str, list[dict]]:
    """Return (outcome, per-check details). Blocked wins over everything."""
    if ctx.defender_events is not None and ex.start_utc:
        events = ctx.defender_events(ex.start_utc, ex.end_utc)
        if events:
            return BLOCKED, [{"check": "defender", "passed": True, "detail": f"{len(events)} event(s)"}]

    details = []
    for spec in checks:
        (name, arg), = spec.items()
        if name not in CHECKS:
            raise ValueError(f"unknown check {name!r}")
        passed, detail = CHECKS[name](ex, ctx, arg)
        details.append({"check": name, "passed": passed, "detail": detail})
    return (SUCCESS if details and all(d["passed"] for d in details) else FAIL), details
