"""Build data/pilot_implementations.csv from the pinned MITRE implementation catalog.

Inclusion decisions are encoded here (not hand-edited in the CSV) so every
catalog entry is accounted for and the decisions are reviewable in one place.
Exclusion codes are defined in PREREGISTRATION.md §3.2.
"""
from __future__ import annotations

import csv
import sys

import pandas as pd

from breakpoint import CATALOG, DATA, PILOT_TECHNIQUES

# (technique, implementation) -> (status, reason_code, duplicate_of, note)
INC = ("include", "", "", "")
DECISIONS: dict[tuple[str, str], tuple[str, str, str, str]] = {
    # T1018 Remote System Discovery
    ("T1018", "ICMP Ping Sweep Discovery"): INC,
    ("T1018", "Net Command SMB Enumeration"): ("include", "", "", "net view may fail without a domain/browser service; oracle outcome feeds RQ3"),
    ("T1018", "Active Directory Computer Object Query"): ("exclude", "E2", "", "requires AD"),
    ("T1018", "ARP Cache Enumeration"): INC,
    ("T1018", "NetBIOS Name Scan (NBTscan)"): ("include", "", "", "nbtscan is a third-party binary; pin its hash"),
    ("T1018", "DNS Cache/Query Enumeration"): INC,
    ("T1018", "WMI Computer Enumeration"): ("include", "", "", "local WMI query only; remote RPC step not executed"),
    ("T1018", "Azure AD Enumeration"): ("exclude", "E2", "", "requires Azure AD tenant"),
    # T1016 System Network Configuration Discovery
    ("T1016", "OS Command Network Configuration Discovery"): INC,
    ("T1016", "System API Network Configuration Discovery"): INC,
    ("T1016", "External Service Public IP Discovery"): ("include", "", "", "needs outbound internet from the lab host"),
    ("T1016", "Network Device CLI Discovery"): ("exclude", "E1", "", "network device, not Windows"),
    ("T1016", "Registry Proxy Configuration Discovery"): INC,
    # T1057 Process Discovery
    ("T1057", "Command-line utility process enumeration"): INC,
    ("T1057", "Native API process enumeration"): INC,
    ("T1057", "WMI process enumeration"): INC,
    ("T1057", "PowerShell process enumeration"): INC,
    ("T1057", "/proc filesystem process enumeration"): ("exclude", "E1", "", "Linux"),
    ("T1057", "Remote service process enumeration"): ("exclude", "E2", "", "requires remote host"),
    # T1082 System Information Discovery
    ("T1082", "Native OS Command System Information Discovery"): INC,
    ("T1082", "Registry Query System Information Discovery"): INC,
    ("T1082", "WMI/PowerShell Query System Information Discovery"): INC,
    ("T1082", "Cloud Metadata API System Information Discovery"): ("exclude", "E2", "", "requires cloud VM"),
    ("T1082", "Network Device CLI System Information Discovery"): ("exclude", "E1", "", "network device, not Windows"),
    ("T1082", "Environment Variable Enumeration System Information Discovery"): INC,
    # T1053.005 Scheduled Task
    ("T1053.005", "Scheduled task creation via schtasks CLI"): INC,
    ("T1053.005", "Scheduled task creation via PowerShell CIM"): INC,
    ("T1053.005", "Remote scheduled task creation via schtasks"): ("exclude", "E2", "", "requires remote host"),
    ("T1053.005", "Hidden scheduled task creation"): INC,
    ("T1053.005", "Create Windows scheduled task via schtasks CLI"): ("exclude", "E4", "Scheduled task creation via schtasks CLI", "same tool and arguments"),
    ("T1053.005", "Create Windows scheduled task via PowerShell cmdlet"): ("exclude", "E4", "Scheduled task creation via PowerShell CIM", "both name Register-ScheduledTask / Invoke-CimMethod"),
    ("T1053.005", "Create hidden scheduled task by deleting Security Descriptor"): ("exclude", "E4", "Hidden scheduled task creation", "same SD-deletion mechanism"),
    ("T1053.005", "Create scheduled task via GhostTask registry manipulation"): ("include", "", "", "third-party binary, needs SYSTEM; pin its hash"),
    # T1543.003 Windows Service
    ("T1543.003", "Create New Windows Service"): ("include", "", "", "catalog merges two different step lists under this name (RQ3 defect)"),
    ("T1543.003", "Modify Existing Service"): INC,
    ("T1543.003", "Remote Service Creation"): ("exclude", "E2", "", "requires remote host"),
    ("T1543.003", "Modify Existing Windows Service"): ("exclude", "E4", "Modify Existing Service", "same ImagePath/ChangeServiceConfig mechanism"),
    ("T1543.003", "Remote Windows Service Creation"): ("exclude", "E2", "", "requires remote host; also near-duplicate of Remote Service Creation"),
}

# Implementations not in the catalog (source=manual); excluded from RQ2-RQ3.
MANUAL = [
    ("T1018", "ARP cache via PowerShell Get-NetNeighbor", "no new process; CIM provider inside powershell.exe"),
]

FIELDS = ["technique_id", "implementation", "source", "status", "reason_code", "duplicate_of", "note"]


def main() -> int:
    df = pd.read_excel(CATALOG, sheet_name="Sheet1")
    df = df[df["ATT&CK Technique ID"].isin(PILOT_TECHNIQUES)]
    catalog = list(dict.fromkeys(zip(df["ATT&CK Technique ID"], df["Technique Implementation"])))

    missing = [k for k in catalog if k not in DECISIONS]
    stale = [k for k in DECISIONS if k not in catalog]
    if missing or stale:
        print("missing decisions:", missing, "\nstale decisions:", stale, file=sys.stderr)
        return 1

    rows = [dict(zip(FIELDS, (t, i, "catalog", *DECISIONS[(t, i)]))) for t, i in catalog]
    rows += [dict(zip(FIELDS, (t, i, "manual", "include", "", "", n))) for t, i, n in MANUAL]

    out = DATA / "pilot_implementations.csv"
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    inc = sum(r["status"] == "include" for r in rows)
    print(f"{out.relative_to(DATA.parent)}: {len(rows)} rows, {inc} included")
    return 0


if __name__ == "__main__":
    sys.exit(main())
