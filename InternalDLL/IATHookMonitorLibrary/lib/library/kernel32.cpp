#include <Windows.h>
#include "log_client.h"
#include "DllMain.h"


DLLExport_C BOOL WINAPI IAT_WriteProcessMemory(
    _In_ HANDLE hProcess,
    _In_ LPVOID lpBaseAddress,
    _In_reads_bytes_(nSize) LPCVOID lpBuffer,
    _In_ SIZE_T nSize,
    _Out_opt_ SIZE_T* lpNumberOfBytesWritten)
{
    auto& client = logClient();
    client.info("WriteProcessMemory(hProcess = %d, lpBaseAddress = 0x%08x, \n"
                "                   lpBuffer = ..., nSize = 0x%04x, PNumberOfBytesWritten = 0x%08x)",
                hProcess, lpBaseAddress,
                nSize, lpNumberOfBytesWritten);

    return WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

DLLExport_C BOOL WINAPI IAT_ReadProcessMemory(
    _In_ HANDLE hProcess,
    _In_ LPCVOID lpBaseAddress,
    _Out_writes_bytes_to_(nSize,*lpNumberOfBytesRead) LPVOID lpBuffer,
    _In_ SIZE_T nSize,
    _Out_opt_ SIZE_T* lpNumberOfBytesRead)
{
    auto& client = logClient();
    client.info("ReadProcessMemory(hProcess = %d, lpBaseAddress = 0x%08x, \n"
                "                  lpBuffer = ..., nSize = 0x%04x, PNumberOfBytesRead = 0x%08x)",
                hProcess, lpBaseAddress,
                nSize, lpNumberOfBytesRead);

    return ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

DLLExport_C HANDLE WINAPI IAT_OpenProcess(
    _In_ DWORD dwDesiredAccess,
    _In_ BOOL bInheritHandle,
    _In_ DWORD dwProcessId)
{
    auto& client = logClient();
    client.info("OpenProcess(dwDesiredAcess=%x, bInheritHandle=%d, dwProcessId=%d)",
                dwDesiredAccess, bInheritHandle, dwProcessId);

    return OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}