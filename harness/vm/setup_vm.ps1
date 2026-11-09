# setup_vm.ps1: run ONCE inside the Hyper-V Windows 11 VM, as Administrator, before creating the clean checkpoint.
# Configures telemetry exactly as pinned in PREREGISTRATION §7. Re-running is safe.
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$lab = 'C:\BPLab'
New-Item -ItemType Directory -Force -Path "$lab\bin", "$lab\breakpoint" | Out-Null

# 1. Defender: exclude ONLY the lab folder; record signature version for §7
Add-MpPreference -ExclusionPath $lab
$sig = (Get-MpComputerStatus).AntivirusSignatureVersion

# 2. Sysmon with the repo's no-filter config (Sysmon64.exe and the XML must be in C:\BPLab\bin)
& "$lab\bin\Sysmon64.exe" -accepteula -i "$lab\breakpoint\harness\vm\sysmon-breakpoint.xml" 2>$null
if ($LASTEXITCODE -ne 0) { & "$lab\bin\Sysmon64.exe" -c "$lab\breakpoint\harness\vm\sysmon-breakpoint.xml" }
wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:1073741824   # 1 GB log

# 3. Security auditing
auditpol /set /subcategory:"Process Creation" /success:enable                 # 4688
auditpol /set /subcategory:"Security System Extension" /success:enable        # 4697 service installed
auditpol /set /subcategory:"Other Object Access Events" /success:enable       # 4698-4702 scheduled tasks
auditpol /set /subcategory:"Registry" /success:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null
wevtutil sl Security /ms:1073741824

# 4. PowerShell script block logging (4104) and module logging
$ps = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
New-Item -Force -Path "$ps\ScriptBlockLogging" | Out-Null
Set-ItemProperty -Path "$ps\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1
New-Item -Force -Path "$ps\ModuleLogging\ModuleNames" | Out-Null
Set-ItemProperty -Path "$ps\ModuleLogging" -Name EnableModuleLogging -Value 1
Set-ItemProperty -Path "$ps\ModuleLogging\ModuleNames" -Name '*' -Value '*'

# 5. Task Scheduler operational log (106 etc.) is off by default
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true

# 6. WMIC (removed by default on recent Windows 11)
if (-not (Get-Command wmic -ErrorAction SilentlyContinue)) {
    Add-WindowsCapability -Online -Name 'WMIC~~~~' | Out-Null
}

# 7. Print the values for PREREGISTRATION §7 and harness/lab.yaml
$os = Get-CimInstance Win32_OperatingSystem
$ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch 'Loopback' -and $_.PrefixOrigin -ne 'WellKnown' } | Select-Object -First 1)
$gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop
[ordered]@{
    computername = $env:COMPUTERNAME
    lab_build    = $os.BuildNumber
    lab_ip       = $ip.IPAddress
    gateway_ip   = $gw
    subnet       = ($gw -split '\.')[0..2] -join '.'
    sysmon       = (Get-Item "$lab\bin\Sysmon64.exe").VersionInfo.FileVersion
    defender_sig = $sig
    wmic         = [bool](Get-Command wmic -ErrorAction SilentlyContinue)
} | Format-List
Write-Host "Done. Next: shut down the VM and create the checkpoint 'bp-clean' on the host."
