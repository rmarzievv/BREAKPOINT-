"""Harness spec stays consistent with the pilot list; oracle logic behaves as ORACLES.md says."""
from pathlib import Path

import pandas as pd
import pytest
import yaml

from harness.oracle import BLOCKED, CHECKS, FAIL, SUCCESS, Context, Execution, evaluate

ROOT = Path(__file__).resolve().parent.parent
IMPLS = yaml.safe_load((ROOT / "harness" / "implementations.yaml").read_text())
KNOWN = {"computername": "PVLAB", "lab_build": "26100", "gateway_ip": "192.168.1.1",
         "gateway_ip_re": r"192\.168\.1\.1", "marker_pid": "4242"}


# ---- spec consistency ----

def test_spec_matches_included_pilot_implementations():
    pilot = pd.read_csv(ROOT / "data" / "pilot_implementations.csv")
    included = set(zip(pilot[pilot.status == "include"].technique_id, pilot[pilot.status == "include"].implementation))
    spec = {(i["technique"], i["implementation"]) for i in IMPLS}
    assert spec == included


def test_ids_unique_and_checks_known():
    ids = [i["id"] for i in IMPLS]
    assert len(ids) == len(set(ids))
    for i in IMPLS:
        assert i["shell"] in {"cmd", "powershell", "exe"}
        assert i["requires"] in {"user", "admin", "system"}
        for check in i["success"]:
            (name,) = check
            assert name in CHECKS, f"{i['id']}: unknown check {name}"


def test_no_markers_in_command_lines():
    for i in IMPLS:
        assert "BPMARK" not in i["command"] and "{run_id}" not in i["command"]


# ---- oracle behaviour ----

def spec(impl_id):
    return next(i for i in IMPLS if i["id"] == impl_id)["success"]


def test_registry_build_success_and_wrong_build_fails():
    ctx = Context(known=KNOWN)
    good = Execution(0, "\r\nHKEY_LOCAL_MACHINE\\...\\CurrentVersion\r\n    CurrentBuild    REG_SZ    26100\r\n")
    wrong = Execution(0, "    CurrentBuild    REG_SZ    19045\r\n")
    header_only = Execution(1, "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\r\n")
    assert evaluate(spec("t1082-reg"), good, ctx)[0] == SUCCESS
    assert evaluate(spec("t1082-reg"), wrong, ctx)[0] == FAIL
    assert evaluate(spec("t1082-reg"), header_only, ctx)[0] == FAIL


def test_exit_zero_alone_is_not_success():
    ctx = Context(known=KNOWN)
    assert evaluate(spec("t1082-systeminfo"), Execution(0, "nothing useful"), ctx)[0] == FAIL


def test_marker_pid_must_be_present():
    ctx = Context(known=KNOWN)
    out = '"Image Name","PID"\r\n"notepad.exe","4242","Console","1","12,000 K"\r\n'
    assert evaluate(spec("t1057-tasklist"), Execution(0, out), ctx)[0] == SUCCESS
    assert evaluate(spec("t1057-tasklist"), Execution(0, out.replace("4242", "4243")), ctx)[0] == FAIL


def test_arp_needs_gateway_with_mac():
    ctx = Context(known=KNOWN)
    out = "Interface: 192.168.1.50 --- 0x5\r\n  192.168.1.1           a4-2b-b0-11-22-33     dynamic\r\n"
    assert evaluate(spec("t1018-arp"), Execution(0, out), ctx)[0] == SUCCESS
    assert evaluate(spec("t1018-arp"), Execution(0, "No ARP Entries Found."), ctx)[0] == FAIL


def test_public_ip_rejects_private():
    ctx = Context(known=KNOWN)
    assert evaluate(spec("t1016-publicip"), Execution(0, "94.200.1.2"), ctx)[0] == SUCCESS
    assert evaluate(spec("t1016-publicip"), Execution(0, "192.168.1.50"), ctx)[0] == FAIL


def test_follow_up_command_checks_use_live_runner():
    calls = []
    def fake_run(shell, command):
        calls.append(command)
        return Execution(0, "TaskName: BPTestCli")
    ctx = Context(known=KNOWN, run=fake_run)
    assert evaluate(spec("t1053-schtasks"), Execution(0, "SUCCESS"), ctx)[0] == SUCCESS
    assert any("schtasks /query /tn BPTestCli" in c for c in calls)


def test_defender_event_means_blocked():
    ctx = Context(known=KNOWN, defender_events=lambda s, e: [{"Id": 1116}])
    ex = Execution(1, "", start_utc="2026-11-04T10:00:00+00:00", end_utc="2026-11-04T10:00:01+00:00")
    assert evaluate(spec("t1082-reg"), ex, ctx)[0] == BLOCKED


def test_no_defender_event_and_failed_checks_is_fail():
    ctx = Context(known=KNOWN, defender_events=lambda s, e: [])
    ex = Execution(5, "Access is denied.", start_utc="2026-11-04T10:00:00+00:00", end_utc="2026-11-04T10:00:01+00:00")
    assert evaluate(spec("t1082-reg"), ex, ctx)[0] == FAIL
