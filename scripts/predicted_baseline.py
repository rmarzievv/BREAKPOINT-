"""Predicted-telemetry baseline: which rules SHOULD fire, judged from expected events.

1. Build the events an analyst expects each implementation to produce:
   - process creation for the shell and the tool it runs (from harness/implementations.yaml)
   - PowerShell script block (4104) for powershell implementations
   - side effects listed in harness/expected_extra.yaml (services, tasks, registry, network)
2. Run every pilot rule over the events of its own logsource.
3. Write:
   data/expected_events.jsonl     the predicted events (review these, not the 400 cells)
   data/predicted_baseline.csv    one row per rule x implementation: should_detect yes/no + matching event

Replaces the manual baseline (PREREGISTRATION §5). Placeholders are filled from harness/lab.example.yaml,
because the prediction is made before the lab's real values are known; none of the pilot rules match on them.
"""
from __future__ import annotations

import csv
import json
import re
import shlex
import sys
from pathlib import Path

import pandas as pd
import yaml

from breakpoint import DATA, ROOT, SIGMA_RULES
from breakpoint.evaluate import load_rule, matches

HARNESS = ROOT / "harness"
PYTHON = r"C:\Program Files\Python312\python.exe"
SYS32 = r"C:\Windows\System32"
POWERSHELL = SYS32 + r"\WindowsPowerShell\v1.0\powershell.exe"

# Windows binaries the pilot uses: image path and PE OriginalFileName
BINARIES = {
    "cmd": (SYS32 + r"\cmd.exe", "Cmd.Exe"),
    "powershell": (POWERSHELL, "PowerShell.EXE"),
    "reg": (SYS32 + r"\reg.exe", "reg.exe"),
    "systeminfo": (SYS32 + r"\systeminfo.exe", "sysinfo.exe"),
    "tasklist": (SYS32 + r"\tasklist.exe", "tasklist.exe"),
    "wmic": (SYS32 + r"\wbem\WMIC.exe", "wmic.exe"),
    "arp": (SYS32 + r"\ARP.EXE", "arp.exe"),
    "ping": (SYS32 + r"\PING.EXE", "ping.exe"),
    "net": (SYS32 + r"\net.exe", "net.exe"),
    "ipconfig": (SYS32 + r"\ipconfig.exe", "ipconfig.exe"),
    "schtasks": (SYS32 + r"\schtasks.exe", "schtasks.exe"),
    "sc": (SYS32 + r"\sc.exe", "sc.exe"),
}
CMD_BUILTINS = {"set", "echo"}
PS_ARGS = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command"


def expand(text: str, known: dict) -> str:
    return re.sub(r"\{(\w+)\}", lambda m: known.get(m.group(1), m.group(0)), text)


def proc(image: str, ofn: str, cmdline: str, parent: str, parent_cmd: str) -> dict:
    return {"logsource": "windows/process_creation", "EventID": "1", "Image": image,
            "OriginalFileName": ofn, "CommandLine": cmdline, "ParentImage": parent,
            "ParentCommandLine": parent_cmd, "IntegrityLevel": "High"}


def child_of_cmd(command: str) -> list[tuple[str, str]]:
    """Tool processes cmd.exe /c <command> spawns: [(binary key, command line)]."""
    m = re.match(r"for /L %i in \((\d+),1,(\d+)\) do @(.+)", command)
    if m:  # ping sweep: one representative child per iteration, first address is enough to predict
        return child_of_cmd(m.group(3).replace("%i", m.group(1)))
    tool = shlex.split(command, posix=False)[0].lower()
    if tool in CMD_BUILTINS:
        return []
    return [(tool, command)]


def events_for(impl: dict, known: dict, extra: dict) -> list[dict]:
    cmd = expand(impl["command"], known)
    shell = impl["shell"]
    ev: list[dict] = []
    if shell == "cmd":
        cmd_line = f'cmd.exe /c {cmd}'
        ev.append(proc(*BINARIES["cmd"], cmd_line, PYTHON, f'"{PYTHON}" -m harness.run'))
        for tool, line in child_of_cmd(cmd):
            image, ofn = BINARIES[tool]
            ev.append(proc(image, ofn, line, BINARIES["cmd"][0], cmd_line))
    elif shell == "powershell":
        ps_line = f"powershell.exe {PS_ARGS} {cmd}"
        ev.append(proc(*BINARIES["powershell"], ps_line, PYTHON, f'"{PYTHON}" -m harness.run'))
        ev.append({"logsource": "windows/ps_script", "EventID": "4104", "ScriptBlockText": cmd})
    elif shell == "exe":
        image = shlex.split(cmd, posix=False)[0]
        ev.append(proc(image, Path(image.replace("\\", "/")).name, cmd, PYTHON, f'"{PYTHON}" -m harness.run'))
    for e in extra.get(impl["id"], []):
        ev.append({k: expand(str(v), known) for k, v in e.items()})
    return ev


def rule_logsource(raw: dict) -> str:
    ls = raw.get("logsource") or {}
    return "/".join(str(ls[k]) for k in ("product", "category", "service") if ls.get(k))


def main() -> int:
    known = {k: str(v) for k, v in yaml.safe_load((HARNESS / "lab.example.yaml").read_text()).items()}
    known.setdefault("username", "bpuser")
    impls = yaml.safe_load((HARNESS / "implementations.yaml").read_text())
    extra = yaml.safe_load((HARNESS / "expected_extra.yaml").read_text())

    events = {i["id"]: events_for(i, known, extra) for i in impls}
    with (DATA / "expected_events.jsonl").open("w", encoding="utf-8") as f:
        for impl_id, evs in events.items():
            for n, e in enumerate(evs):
                f.write(json.dumps({"impl_id": impl_id, "n": n, **e}, ensure_ascii=False) + "\n")

    pilot_rules = pd.read_csv(DATA / "pilot_rules.csv")
    by_tech: dict[str, list[dict]] = {}
    for i in impls:
        by_tech.setdefault(i["technique"], []).append(i)

    rows = []
    for _, r in pilot_rules.iterrows():
        rule = load_rule(next(SIGMA_RULES.rglob(r.rule_file)))
        ls = rule_logsource(rule.raw)
        for tech in r.pilot_techniques.split(";"):
            for impl in by_tech.get(tech, []):
                hits = [e for e in events[impl["id"]]
                        if e["logsource"] == ls and matches(rule, {k: v for k, v in e.items() if k != "logsource"})]
                rows.append({"technique_id": tech, "rule_file": r.rule_file, "implementation": impl["implementation"],
                             "impl_id": impl["id"], "rule_logsource": ls,
                             "should_detect": "yes" if hits else "no",
                             "matching_event": hits[0].get("CommandLine") or hits[0].get("TargetObject")
                             or hits[0].get("ScriptBlockText") or hits[0].get("EventID") if hits else ""})

    with (DATA / "predicted_baseline.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    yes = sum(r["should_detect"] == "yes" for r in rows)
    print(f"expected events: {sum(map(len, events.values()))} for {len(events)} implementations")
    print(f"predicted_baseline.csv: {len(rows)} cells, should detect: {yes}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
