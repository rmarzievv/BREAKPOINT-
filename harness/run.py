"""BREAKPOINT harness: execute pilot implementations on PVLAB and record oracle outcomes.

Run on the Windows lab host from an elevated prompt (admin implementations),
and separately as SYSTEM for `requires: system` ones:

    python -m harness.run                    # all implementations the current privilege allows
    python -m harness.run --only t1082-reg   # one implementation
    python -m harness.run --dry-run          # print what would run, execute nothing

Output: results/<run_id>/runs.jsonl, one line per execution:
    run_id, impl_id, technique, implementation, rep, start_utc, end_utc,
    harness_pid, child_pid, exit_code, stdout, stderr, outcome, checks

Event linking (Sysmon ProcessGuid) happens later from these PIDs and time windows.
The harness never puts markers in command lines.
"""
from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import yaml

from harness.oracle import Context, Execution, evaluate

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
MAX_OUT = 64 * 1024
GAP_SECONDS = 5  # pause between executions so time windows never overlap

DEFENDER_QUERY = (
    "$e = Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-Windows Defender/Operational';"
    "Id=1116,1117,1121; StartTime=[datetime]'{start}'; EndTime=[datetime]'{end}'}} -ErrorAction SilentlyContinue;"
    "if ($e) {{ $e | Select-Object Id,TimeCreated,Message | ConvertTo-Json -Compress }} else {{ '[]' }}"
)


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def argv_for(shell: str, command: str) -> list[str] | str:
    if shell == "cmd":
        return ["cmd.exe", "/c", command]
    if shell == "powershell":
        return ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command]
    if shell == "exe":
        return command  # Windows CreateProcess parses the command line itself
    raise ValueError(f"unknown shell {shell!r}")


def execute(shell: str, command: str, timeout: int = 120) -> Execution:
    start = now_utc()
    try:
        p = subprocess.Popen(argv_for(shell, command), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             stdin=subprocess.DEVNULL)
        out, err = p.communicate(timeout=timeout)
        code = p.returncode
    except FileNotFoundError as e:
        return Execution(None, "", str(e), start, now_utc(), None)
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
        code = None
    return Execution(code, _decode(out), _decode(err), start, now_utc(), p.pid)


def _decode(b: bytes) -> str:
    for enc in ("utf-8", "cp866", "cp1252"):
        try:
            return b.decode(enc)[:MAX_OUT]
        except UnicodeDecodeError:
            continue
    return b.decode("utf-8", "replace")[:MAX_OUT]


def privilege() -> str:
    who = subprocess.run(["whoami"], capture_output=True, text=True).stdout.strip().lower()
    if who == "nt authority\\system":
        return "system"
    return "admin" if ctypes.windll.shell32.IsUserAnAdmin() else "user"


PRIV_RANK = {"user": 0, "admin": 1, "system": 2}


def defender_events(start: str, end: str) -> list[dict]:
    # small slack on both sides: Defender logs asynchronously
    s = (dt.datetime.fromisoformat(start) - dt.timedelta(seconds=2)).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    e = (dt.datetime.fromisoformat(end) + dt.timedelta(seconds=10)).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    time.sleep(3)
    ex = execute("powershell", DEFENDER_QUERY.format(start=s, end=e))
    try:
        data = json.loads(ex.stdout or "[]")
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else [data]


def load_known() -> dict[str, str]:
    path = HERE / "lab.yaml"
    if not path.exists():
        sys.exit("harness/lab.yaml missing: copy lab.example.yaml and fill in the lab's true values")
    known = {k: str(v) for k, v in yaml.safe_load(path.read_text()).items()}
    known["gateway_ip_re"] = re.escape(known["gateway_ip"])
    known["subnet_re"] = re.escape(known["subnet"])
    return known


def run_steps(steps: list[dict] | None, ctx: Context) -> None:
    for step in steps or []:
        execute(step["shell"], ctx.expand(step["command"]))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="*", help="implementation ids")
    ap.add_argument("--reps", type=int)
    ap.add_argument("--rep", type=int, default=1, help="number of the first repetition (host orchestrator runs one rep per VM revert)")
    ap.add_argument("--out", type=Path, help="output directory (default results/<run_id>)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    impls = yaml.safe_load((HERE / "implementations.yaml").read_text())
    if args.only:
        impls = [i for i in impls if i["id"] in args.only]
    known = load_known()
    reps = args.reps or int(known.get("repetitions", 3))

    if args.dry_run:
        ctx = Context(known={**known, "marker_pid": "<marker_pid>"})
        for i in impls:
            print(f"[{i['requires']:6}] {i['id']:20} {i['shell']:10} {ctx.expand(i['command'])}")
        return 0

    priv = privilege()
    run_id = dt.datetime.now().strftime("%Y%m%d-%H%M%S") + f"-{priv}"
    out_dir = args.out or ROOT / "results" / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    out = (out_dir / "runs.jsonl").open("a", encoding="utf-8")
    print(f"run {run_id}: privilege={priv}, harness_pid={os.getpid()}")

    for impl in impls:
        if PRIV_RANK[impl["requires"]] > PRIV_RANK[priv] or (impl["requires"] != "system" and priv == "system"):
            continue  # admin/user implementations run in the elevated pass, system ones in the SYSTEM pass
        for rep in range(args.rep, args.rep + reps):
            marker = subprocess.Popen(["notepad.exe"]) if impl.get("marker") else None
            ctx = Context(known={**known, "marker_pid": str(marker.pid) if marker else ""},
                          run=execute, defender_events=defender_events)
            run_steps(impl.get("setup"), ctx)
            ex = execute(impl["shell"], ctx.expand(impl["command"]))
            outcome, checks = evaluate(impl["success"], ex, ctx)
            run_steps(impl.get("cleanup"), ctx)
            if marker:
                marker.kill()

            out.write(json.dumps({
                "run_id": run_id, "impl_id": impl["id"], "technique": impl["technique"],
                "implementation": impl["implementation"], "rep": rep,
                "start_utc": ex.start_utc, "end_utc": ex.end_utc,
                "harness_pid": os.getpid(), "child_pid": ex.pid,
                "exit_code": ex.exit_code, "stdout": ex.stdout, "stderr": ex.stderr,
                "outcome": outcome, "checks": checks,
            }, ensure_ascii=False) + "\n")
            out.flush()
            print(f"  {impl['id']:20} rep {rep}: {outcome}")
            time.sleep(GAP_SECONDS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
