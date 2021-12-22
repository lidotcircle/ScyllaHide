#pragma once

#include <ntdll/ntdll.h>

#define STATUS_PRIVILEGE_NOT_HELD ((NTSTATUS)0xC0000061L)
#define STATUS_PORT_NOT_SET ((NTSTATUS)0xC0000353L)
#define STATUS_HANDLE_NOT_CLOSABLE ((NTSTATUS)0xC0000235L)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009AL)
#define PROCESS_DEBUG_INHERIT 0x00000001 // default for a non-debugged process
#define PROCESS_NO_DEBUG_INHERIT 0x00000002 // default for a debugged process
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004

#ifndef _WIN64
#define NAKED __declspec(naked)
#else
#define NAKED
#endif

typedef struct _SAVE_DEBUG_REGISTERS
{
    DWORD dwThreadId;
    DWORD_PTR Dr0;
    DWORD_PTR Dr1;
    DWORD_PTR Dr2;
    DWORD_PTR Dr3;
    DWORD_PTR Dr6;
    DWORD_PTR Dr7;
} SAVE_DEBUG_REGISTERS;

#define DLLExport __declspec(dllexport)
#define DLLExport_C extern "C" __declspec(dllexport)
