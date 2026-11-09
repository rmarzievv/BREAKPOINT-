/* netcfg: T1016 System API network configuration discovery (catalog variant A).
 * GetAdaptersAddresses, prints "adapter<TAB>IPv4" per unicast address. */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    ULONG len = 16 * 1024;
    IP_ADAPTER_ADDRESSES *buf = NULL;
    ULONG rc;
    for (int i = 0; i < 3; i++) {
        buf = (IP_ADAPTER_ADDRESSES *)malloc(len);
        rc = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, NULL, buf, &len);
        if (rc != ERROR_BUFFER_OVERFLOW) break;
        free(buf);
        buf = NULL;
    }
    if (rc != NO_ERROR) return 1;
    for (IP_ADAPTER_ADDRESSES *a = buf; a; a = a->Next) {
        for (IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress; u; u = u->Next) {
            char ip[INET_ADDRSTRLEN];
            struct sockaddr_in *sa = (struct sockaddr_in *)u->Address.lpSockaddr;
            inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
            printf("%ls\t%s\n", a->FriendlyName, ip);
        }
    }
    free(buf);
    return 0;
}
