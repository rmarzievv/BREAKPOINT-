# harness

Executes every pilot implementation on PVLAB and records an oracle outcome: success, fail or blocked.
Pattern: Red Canary AtomicTestHarnesses. No markers in command lines; events are linked later via PIDs, Sysmon ProcessGuid and time windows.

Files:
- ORACLES.md — human-readable oracles
- implementations.yaml — executable spec (same content, CI checks it matches data/pilot_implementations.csv)
- oracle.py — check logic, unit-tested off Windows
- run.py — the runner (Windows only)
- lab.example.yaml — template for the lab's known true values


## Setup on PVLAB (once)

- [ ] Python 3.12 + `pip install pyyaml`
- [ ] C:\BPLab created, Defender exclusion only for this folder
- [ ] `copy harness\lab.example.yaml harness\lab.yaml`, fill in real values (same as PREREGISTRATION §7)
- [ ] C:\BPLab\bin\ contains:
  - enumproc.exe + enumproc.ps1 — CreateToolhelp32Snapshot, print one PID per line
  - netcfg.exe + netcfg.ps1 — GetAdaptersAddresses, print IPv4 addresses
  - nbtscan.exe, GhostTask.exe — third-party, SHA256 pinned in §7
  - bpsvc.exe, bpsvc2.exe — any harmless exe; services are created, never started
  - cleanup_task.ps1 — removes a task's TaskCache Tree/Tasks/Plain keys and XML
- [ ] wmic present (install the WMIC optional feature if missing)
- [ ] Sysmon + auditing configured, background collection running


## Run

    python -m harness.run --dry-run           # check commands and placeholders
    python -m harness.run                     # elevated prompt: user + admin implementations
    psexec -s -i python -m harness.run        # SYSTEM pass: hidden task, GhostTask

Results: results/<run_id>/runs.jsonl
