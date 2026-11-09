# netcfg.ps1: T1016 System API network configuration (variant B, PowerShell P/Invoke).
# Calls iphlpapi!GetAdaptersAddresses directly from powershell.exe and prints IPv4 unicast addresses.
Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Runtime.InteropServices;
public static class BPIpHlp {
    [DllImport("iphlpapi.dll")] public static extern uint GetAdaptersAddresses(uint family, uint flags, IntPtr reserved, IntPtr buf, ref uint len);
    // Walk IP_ADAPTER_ADDRESSES_LH -> FirstUnicastAddress -> SOCKET_ADDRESS -> sockaddr_in (x64 offsets).
    public static string[] IPv4() {
        uint len = 16384; IntPtr buf = Marshal.AllocHGlobal((int)len);
        uint rc = GetAdaptersAddresses(2, 0x2 | 0x4, IntPtr.Zero, buf, ref len);
        if (rc == 111) { Marshal.FreeHGlobal(buf); buf = Marshal.AllocHGlobal((int)len); rc = GetAdaptersAddresses(2, 0x2 | 0x4, IntPtr.Zero, buf, ref len); }
        if (rc != 0) { Marshal.FreeHGlobal(buf); return null; }
        var list = new System.Collections.Generic.List<string>();
        for (IntPtr a = buf; a != IntPtr.Zero; a = Marshal.ReadIntPtr(a, 8)) {          // Next
            for (IntPtr u = Marshal.ReadIntPtr(a, 24); u != IntPtr.Zero; u = Marshal.ReadIntPtr(u, 8)) {  // FirstUnicastAddress, Next
                IntPtr sa = Marshal.ReadIntPtr(u, 16);                                // Address.lpSockaddr
                byte[] ip = new byte[4]; Marshal.Copy(IntPtr.Add(sa, 4), ip, 0, 4);  // sin_addr
                list.Add(new IPAddress(ip).ToString());
            }
        }
        Marshal.FreeHGlobal(buf);
        return list.ToArray();
    }
}
'@
$ips = [BPIpHlp]::IPv4()
if ($null -eq $ips) { exit 1 }
$ips
exit 0
