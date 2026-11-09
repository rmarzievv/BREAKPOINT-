# enumproc.ps1: T1057 Native API process enumeration (variant B, PowerShell P/Invoke).
# Same API as enumproc.c, called inside powershell.exe: no new binary on disk.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class BPToolhelp {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct PROCESSENTRY32 {
        public uint dwSize; public uint cntUsage; public uint th32ProcessID; public IntPtr th32DefaultHeapID;
        public uint th32ModuleID; public uint cntThreads; public uint th32ParentProcessID; public int pcPriClassBase;
        public uint dwFlags; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
    }
    [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] public static extern bool Process32FirstW(IntPtr snap, ref PROCESSENTRY32 pe);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] public static extern bool Process32NextW(IntPtr snap, ref PROCESSENTRY32 pe);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
}
'@
$snap = [BPToolhelp]::CreateToolhelp32Snapshot(2, 0)   # TH32CS_SNAPPROCESS
if ($snap -eq [IntPtr]-1) { exit 1 }
$pe = New-Object BPToolhelp+PROCESSENTRY32
$pe.dwSize = [Runtime.InteropServices.Marshal]::SizeOf($pe)
if (-not [BPToolhelp]::Process32FirstW($snap, [ref]$pe)) { exit 2 }
do { "{0}`t{1}" -f $pe.th32ProcessID, $pe.szExeFile } while ([BPToolhelp]::Process32NextW($snap, [ref]$pe))
[void][BPToolhelp]::CloseHandle($snap)
exit 0
