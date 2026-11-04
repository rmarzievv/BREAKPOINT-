# Oracles

Every implementation returns one outcome:
- success — all checks below pass
- blocked — Defender / ASR event (1116, 1117, 1121) in the execution time window
- fail — anything else

Conventions:
- Lab folder: C:\BPLab (the only Defender exclusion)
- Test artefacts are named BPTest*, so cleanup never touches real objects
- Persistence implementations clean up after the oracle runs; cleanup is not part of the measured execution
- $env:COMPUTERNAME and the lab build (PREREGISTRATION §7) are the known true values


## T1082 — System Information Discovery

### Registry Query System Information Discovery
Command:
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuild
Success:
- exit code 0
- output contains CurrentBuild with a number
- number == lab build

### Native OS Command System Information Discovery
Command:
    systeminfo
Success:
- exit code 0
- output contains $env:COMPUTERNAME

### WMI/PowerShell Query System Information Discovery
Command:
    powershell -c "Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber"
Success:
- exit code 0
- output == lab build

### Environment Variable Enumeration System Information Discovery
Command:
    cmd /c set
Success:
- exit code 0
- output contains COMPUTERNAME=$env:COMPUTERNAME
- output contains PROCESSOR_ARCHITECTURE=


## T1057 — Process Discovery

Known true value: the harness starts a marker process (notepad.exe, PID recorded) before each run.

### Command-line utility process enumeration
Command:
    tasklist /fo csv
Success:
- exit code 0
- output contains the marker PID

### WMI process enumeration
Command:
    wmic process get ProcessId,Name /format:csv
Success:
- exit code 0
- output contains the marker PID
Note: wmic is removed by default on recent Windows 11 builds but still common on Windows 10 hosts. If missing on PVLAB, install the WMIC optional feature and record it in PREREGISTRATION §7.

### PowerShell process enumeration
Command:
    powershell -c "Get-Process | Select-Object -ExpandProperty Id"
Success:
- exit code 0
- output contains the marker PID

### Native API process enumeration
Two variants, same API, different telemetry (tests H3):

Variant A — compiled C (catalog):
    C:\BPLab\bin\enumproc.exe   (CreateToolhelp32Snapshot + Process32First/Next)

Variant B — PowerShell P/Invoke (manual):
    powershell -c "Add-Type ... CreateToolhelp32Snapshot ..."   (no new binary, API called inside powershell.exe)

Success (both):
- exit code 0
- output contains the marker PID


## T1018 — Remote System Discovery

Known true value: the lab gateway IP and MAC, recorded in PREREGISTRATION §7.

### ARP Cache Enumeration
Command:
    arp -a
Success:
- exit code 0
- output contains the gateway IP with a MAC address

### ARP cache via PowerShell Get-NetNeighbor (manual)
Command:
    powershell -c "Get-NetNeighbor -AddressFamily IPv4 | Select-Object IPAddress,LinkLayerAddress"
Success:
- exit code 0
- output contains the gateway IP

### ICMP Ping Sweep Discovery
Command:
    cmd /c "for /L %i in (1,1,20) do @ping -n 1 -w 200 <subnet>.%i"
Success:
- at least one "Reply from" line
- the gateway IP replied

### Net Command SMB Enumeration
Command:
    net view
Success:
- exit code 0
- output lists at least one host
Note: often fails without a domain or the browser service. Expected outcome is fail; kept for RQ3 (executability).

### NetBIOS Name Scan (NBTscan)
Command:
    C:\BPLab\bin\nbtscan.exe <subnet>.0/24   (hash pinned in PREREGISTRATION §7)
Success:
- exit code 0
- output contains at least one IP with a NetBIOS name

### DNS Cache/Query Enumeration
Command:
    ipconfig /displaydns
Setup: harness resolves bp-oracle.example.com (or another known name) first.
Success:
- exit code 0
- output contains the known name

### WMI Computer Enumeration
Command:
    powershell -c "Get-CimInstance Win32_ComputerSystem | Select-Object -ExpandProperty Name"
Success:
- exit code 0
- output == $env:COMPUTERNAME


## T1016 — System Network Configuration Discovery

### OS Command Network Configuration Discovery
Command:
    ipconfig /all
Success:
- exit code 0
- output contains the lab host IP

### System API Network Configuration Discovery
Two variants, same API, different telemetry (tests H3):

Variant A — compiled C (catalog):
    C:\BPLab\bin\netcfg.exe   (GetAdaptersAddresses)

Variant B — PowerShell P/Invoke (manual):
    powershell -c "Add-Type ... GetAdaptersAddresses ..."

Success (both):
- exit code 0
- output contains the lab host IP

### External Service Public IP Discovery
Command:
    powershell -c "(Invoke-RestMethod https://api.ipify.org)"
Success:
- exit code 0
- output is a valid IPv4 address
- address is not private (10/8, 172.16/12, 192.168/16)

### Registry Proxy Configuration Discovery
Command:
    reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable
Success:
- exit code 0
- output contains ProxyEnable with a 0x value


## T1053.005 — Scheduled Task

Payload for every task: cmd /c echo bp > C:\BPLab\task_ran.txt

### Scheduled task creation via schtasks CLI
Command:
    schtasks /create /tn BPTestCli /tr "<payload>" /sc once /st 23:59 /f
Success:
- exit code 0
- schtasks /query /tn BPTestCli succeeds
Cleanup: schtasks /delete /tn BPTestCli /f

### Scheduled task creation via PowerShell CIM
Command:
    powershell -c "Register-ScheduledTask -TaskName BPTestCim -Action (New-ScheduledTaskAction -Execute cmd.exe -Argument '/c echo bp > C:\BPLab\task_ran.txt') -Trigger (New-ScheduledTaskTrigger -Once -At 23:59)"
Success:
- exit code 0
- Get-ScheduledTask -TaskName BPTestCim returns the task
Cleanup: Unregister-ScheduledTask BPTestCim -Confirm:$false

### Hidden scheduled task creation
Command (as SYSTEM):
    1. schtasks /create /tn BPTestHidden /tr "<payload>" /sc once /st 23:59 /f
    2. reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\BPTestHidden" /v SD /f
Success:
- registry key Tree\BPTestHidden exists
- value SD is absent
- schtasks /query /tn BPTestHidden no longer finds it (the task is hidden)
Cleanup: delete the Tree, Tasks and Plain entries for the task GUID, then the XML in C:\Windows\System32\Tasks

### Create scheduled task via GhostTask registry manipulation
Command (as SYSTEM):
    C:\BPLab\bin\GhostTask.exe localhost add BPTestGhost "cmd.exe" "/c echo bp > C:\BPLab\task_ran.txt" ...   (hash pinned)
Success:
- registry key TaskCache\Tree\BPTestGhost exists
- no Task Scheduler "task registered" event (Microsoft-Windows-TaskScheduler/Operational 106) for it
Cleanup: GhostTask delete, then remove leftover keys


## T1543.003 — Windows Service

### Create New Windows Service
Command:
    sc create BPTestSvc binPath= "C:\BPLab\bin\bpsvc.exe" start= demand
Success:
- exit code 0
- sc query BPTestSvc succeeds
- HKLM\SYSTEM\CurrentControlSet\Services\BPTestSvc exists
Cleanup: sc delete BPTestSvc

### Modify Existing Service
Setup: the harness creates BPTestSvcMod (pointing to bpsvc.exe) first, so no real service is touched.
Command:
    sc config BPTestSvcMod binPath= "C:\BPLab\bin\bpsvc2.exe"
Success:
- exit code 0
- ImagePath of BPTestSvcMod in the registry == C:\BPLab\bin\bpsvc2.exe
Cleanup: sc delete BPTestSvcMod
