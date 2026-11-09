# harness

Executes every pilot implementation inside a Hyper-V VM on PVLAB, reverting to a clean checkpoint before every execution, and records an oracle outcome: success, fail or blocked.
Pattern: Red Canary AtomicTestHarnesses. No markers in command lines; events are linked later via PIDs, Sysmon ProcessGuid and time windows.

Files:
- ORACLES.md — human-readable oracles
- implementations.yaml — executable spec (CI checks it matches data/pilot_implementations.csv)
- expected_extra.yaml — side-effect events we expect, used by the predicted baseline
- oracle.py — check logic, unit-tested off Windows
- run.py — runs implementations inside the VM
- host/run_vm.ps1 — runs on the PVLAB host: revert → execute once → export logs → repeat
- vm/setup_vm.ps1 — one-time telemetry setup inside the VM
- vm/sysmon-breakpoint.xml — Sysmon config with no filters
- bin/ — helper programs (C + PowerShell); `bin/build.sh` cross-compiles them, output in bin/out (not in git)


## One-time setup

On the PVLAB host:
- [ ] Enable Hyper-V, create a Windows 11 VM named BPLab, user with admin rights
- [ ] Enable Guest Services for the VM (PowerShell Direct needs the VM's credentials)

Inside the VM:
- [ ] Install Python 3.12 (add to PATH), `pip install pyyaml`
- [ ] Copy the repo to C:\BPLab\breakpoint
- [ ] Copy harness\bin\out\* to C:\BPLab\bin\
- [ ] Download into C:\BPLab\bin\: Sysmon64.exe, PsExec64.exe (Sysinternals), nbtscan.exe, GhostTask.exe
- [ ] Run `harness\vm\setup_vm.ps1` as Administrator, copy its output into PREREGISTRATION §7 and harness\lab.yaml
- [ ] Shut down the VM

On the host:
- [ ] `Checkpoint-VM -Name BPLab -SnapshotName bp-clean`


## Run

On the host, elevated PowerShell, from the repo folder:

    .\harness\host\run_vm.ps1 -VMName BPLab -Ids t1082-reg -Reps 1    # smoke test
    .\harness\host\run_vm.ps1 -VMName BPLab                           # everything

Inside the VM, without revert (debugging only):

    python -m harness.run --dry-run
    python -m harness.run --only t1082-reg

Results: results/<timestamp>/<impl_id>/rep<N>/ with runs.jsonl and evtx/ (Sysmon, Security, System, PowerShell, TaskScheduler, Defender).
