# run_vm.ps1: run on the PVLAB HOST (Hyper-V), as Administrator.
# For every implementation and repetition: revert VM to the clean checkpoint, run ONE execution inside it,
# export that execution's telemetry, copy results out. Revert-per-execution is what PREREGISTRATION §4 requires.
#
#   .\harness\host\run_vm.ps1 -VMName BPLab -Ids t1082-reg,t1082-systeminfo
#   .\harness\host\run_vm.ps1 -VMName BPLab              # all implementations
param(
    [string]$VMName = 'BPLab',
    [string]$Checkpoint = 'bp-clean',
    [string[]]$Ids,
    [int]$Reps = 3,
    [string]$Out = (Join-Path $PSScriptRoot '..\..\results')
)
$ErrorActionPreference = 'Stop'
$cred = Get-Credential -Message "Credentials of the lab user inside the VM (admin)"
$impls = (Get-Content (Join-Path $PSScriptRoot '..\implementations.yaml') -Raw) -split "`n" |
    Where-Object { $_ -match '^- id: (\S+)' } | ForEach-Object { $Matches[1] }
if ($Ids) { $impls = $impls | Where-Object { $_ -in $Ids } }
$logs = 'Microsoft-Windows-Sysmon/Operational', 'Security', 'System',
        'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-TaskScheduler/Operational',
        'Microsoft-Windows-Windows Defender/Operational'
$runRoot = Join-Path $Out (Get-Date -Format 'yyyyMMdd-HHmmss')
New-Item -ItemType Directory -Force -Path $runRoot | Out-Null

foreach ($id in $impls) {
    foreach ($rep in 1..$Reps) {
        Write-Host "[$id rep $rep] revert"
        Stop-VM -Name $VMName -TurnOff -Force -ErrorAction SilentlyContinue
        Restore-VMCheckpoint -VMName $VMName -Name $Checkpoint -Confirm:$false
        Start-VM -Name $VMName
        while ((Get-VMIntegrationService -VMName $VMName -Name Heartbeat).PrimaryStatusDescription -ne 'OK') { Start-Sleep 2 }
        Start-Sleep 20   # let boot-time noise settle

        $s = New-PSSession -VMName $VMName -Credential $cred
        $dest = Join-Path $runRoot "$id\rep$rep"
        New-Item -ItemType Directory -Force -Path $dest | Out-Null

        # One execution inside the VM. SYSTEM implementations are elevated with PsExec -s, not a scheduled task
        # (that would add T1053 telemetry). PsExec installs PSEXESVC (7045): outside the harness process tree,
        # so event linking excludes it; noted as a threat to validity.
        Invoke-Command -Session $s -ArgumentList $id, $rep -ScriptBlock {
            param($id, $rep)
            Set-Location C:\BPLab\breakpoint
            $req = (Select-String -Path harness\implementations.yaml -Pattern "^- id: $id$" -Context 0, 8).Context.PostContext |
                   Where-Object { $_ -match 'requires: (\w+)' } | ForEach-Object { $Matches[1] } | Select-Object -First 1
            if ($req -eq 'system') {
                & C:\BPLab\bin\PsExec64.exe -accepteula -s -w C:\BPLab\breakpoint python -m harness.run --only $id --reps 1 --rep $rep --out C:\BPLab\out 2>&1
            } else {
                python -m harness.run --only $id --reps 1 --rep $rep --out C:\BPLab\out 2>&1
            }
            New-Item -ItemType Directory -Force -Path C:\BPLab\out\evtx | Out-Null
            foreach ($log in $using:logs) {
                $name = ($log -replace '[/ ]', '_') + '.evtx'
                wevtutil epl $log "C:\BPLab\out\evtx\$name" /ow:true
            }
        }
        Copy-Item -FromSession $s -Path C:\BPLab\out\* -Destination $dest -Recurse -Force
        Remove-PSSession $s
    }
}
Stop-VM -Name $VMName -TurnOff -Force
Write-Host "Results: $runRoot"
