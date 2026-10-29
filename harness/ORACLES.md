# Oracles

Every implementation returns one outcome:
- success — all checks below pass
- blocked — Defender / ASR event (1116, 1117, 1121) in the execution time window
- fail — anything else


## T1082 — Registry Query System Information Discovery

Command:
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuild

Success:
- exit code 0
- output contains CurrentBuild with a number
- number == lab build (PREREGISTRATION §7)


## T1082 — Native OS Command System Information Discovery

Command:
    systeminfo

Success:
- exit code 0
- output contains $env:COMPUTERNAME