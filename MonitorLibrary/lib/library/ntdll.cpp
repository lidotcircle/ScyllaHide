#include <Windows.h>
#include "exchange_data.h"
#include "log_client.h"
#include "DllMain.h"


DLLExport_C NTSTATUS NTAPI HookedNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferSize, PULONG NumberofBytesWritten)
{
    auto& client = logClient();
    client.info("NtWriteVirtualMemory(ProcessHandle = %d, BaseAddress = 0x%08x, \n"
                "                     Buffer = ..., BufferSize = 0x%04x, PNumberOfBytesWritten = 0x%08x)",
                ProcessHandle, BaseAddress,
                BufferSize, NumberofBytesWritten);

    auto dNtWriteVirtualMemory = exchange_data.lookup_trampoline<decltype(&NtWriteVirtualMemory)>(&NtWriteVirtualMemory);
    return dNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberofBytesWritten);
}

DLLExport_C NTSTATUS NTAPI HookedNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded)
{
    auto& client = logClient();
    client.info("NtReadVirtualMemory(ProcessHandle = %d, BaseAddress = 0x%08x, \n"
                "                    Buffer = ..., NumberOfBytesToRead = 0x%08x, \n"
                "                    PNumberOfBytesReaded = 0x%08x)",
                ProcessHandle, BaseAddress, NumberOfBytesToRead, NumberOfBytesReaded);

    auto dNtReadVirtualMemory = exchange_data.lookup_trampoline<decltype(&NtReadVirtualMemory)>(&NtReadVirtualMemory);
    return dNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
}

DLLExport_C NTSTATUS NTAPI HookedNtOpenProcess(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
)
{
    auto dNtOpenProcess = exchange_data.lookup_trampoline<decltype(&NtOpenProcess)>(&NtOpenProcess);
    auto ans = dNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

    auto& client = logClient();
    client.info("NtOpenProcess(PProcessHandle = 0x%08x, 0xDesiredAccess = %08x, \n"
                "              ObjectAttributes = 0x%04x, ClientId = 0x%08x) => %d",
                ProcessHandle, DesiredAccess, ObjectAttributes, ClientId, *ProcessHandle);

    return ans;
}
