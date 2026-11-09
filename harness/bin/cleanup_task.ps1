# cleanup_task.ps1 <TaskName>: remove a (possibly hidden or registry-only) scheduled task completely.
# Used only by harness cleanup steps; never touches tasks not named BPTest*.
param([Parameter(Mandatory)][ValidatePattern('^BPTest')][string]$TaskName)
$cache = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache'
$tree = Join-Path $cache "Tree\$TaskName"
$id = (Get-ItemProperty -Path $tree -Name Id -ErrorAction SilentlyContinue).Id
if ($id) {
    foreach ($sub in 'Tasks', 'Plain', 'Boot', 'Logon', 'Maintenance') {
        Remove-Item -Path (Join-Path $cache "$sub\$id") -Recurse -Force -ErrorAction SilentlyContinue
    }
}
Remove-Item -Path $tree -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:SystemRoot\System32\Tasks\$TaskName" -Force -ErrorAction SilentlyContinue
schtasks.exe /delete /tn $TaskName /f 2>$null | Out-Null
exit 0
