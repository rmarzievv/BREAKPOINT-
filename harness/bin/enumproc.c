/* enumproc: T1057 Native API process enumeration (catalog variant A).
 * CreateToolhelp32Snapshot + Process32First/Next, prints "PID<TAB>name" per line. */
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

int main(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 1;
    PROCESSENTRY32W pe = { .dwSize = sizeof(pe) };
    if (!Process32FirstW(snap, &pe)) { CloseHandle(snap); return 2; }
    do {
        wprintf(L"%lu\t%ls\n", pe.th32ProcessID, pe.szExeFile);
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);
    return 0;
}
