#include "HookMain.h"
#include "LogClient.h"
#include <stdio.h>

#pragma intrinsic(_ReturnAddress)

#include "HookedFunctions.h"
#include "HookHelper.h"
#include "Tls.h"
#include "scylla/exchange.h"

extern "C" DLLExport HOOK_DLL_DATA HookDllData  =  { 0 };
extern "C" DLLExport ExchangeData exchange_data =  { 0 };

void FakeCurrentParentProcessId(PSYSTEM_PROCESS_INFORMATION pInfo);
void FakeCurrentOtherOperationCount(PSYSTEM_PROCESS_INFORMATION pInfo);
void FilterHandleInfo(PSYSTEM_HANDLE_INFORMATION pHandleInfo, PULONG pReturnLengthAdjust);
void FilterHandleInfoEx(PSYSTEM_HANDLE_INFORMATION_EX pHandleInfoEx, PULONG pReturnLengthAdjust);
void FilterProcess(PSYSTEM_PROCESS_INFORMATION pInfo);
void FilterObjects(POBJECT_TYPES_INFORMATION pObjectTypes);
void FilterObject(POBJECT_TYPE_INFORMATION pObject, bool zeroTotal);
void FilterHwndList(HWND * phwndFirst, PUINT pcHwndNeeded);

SAVE_DEBUG_REGISTERS ArrayDebugRegister[100] = { 0 }; //Max 100 threads

// https://forum.tuts4you.com/topic/40011-debugme-vmprotect-312-build-886-anti-debug-method-improved/#comment-192824
// https://github.com/x64dbg/ScyllaHide/issues/47
// https://github.com/mrexodia/TitanHide/issues/27
#define BACKUP_RETURNLENGTH() \
    ULONG TempReturnLength = 0; \
    if(ReturnLength != nullptr) \
        TempReturnLength = *ReturnLength

#define RESTORE_RETURNLENGTH() \
    if(ReturnLength != nullptr) \
        (*ReturnLength) = TempReturnLength

static ULONG ValueProcessBreakOnTermination = FALSE;
static ULONG ValueProcessDebugFlags = PROCESS_DEBUG_INHERIT; // actual value is no inherit
static bool IsProcessHandleTracingEnabled = false;

#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER         ((DWORD   )0xC000000DL)
#endif

// Instrumentation callback

static LONG volatile InstrumentationCallbackHookInstalled = 0;
static ULONG NumManualSyscalls = 0;

extern "C"
ULONG_PTR
NTAPI
InstrumentationCallback(
    _In_ ULONG_PTR ReturnAddress, // ECX/R10
    _Inout_ ULONG_PTR ReturnVal // EAX/RAX
    )
{
    if (InterlockedOr(TlsGetInstrumentationCallbackDisabled(), 0x1) == 0x1)
        return ReturnVal; // Do not recurse

    const PVOID ImageBase = NtCurrentPeb()->ImageBaseAddress;
    const PIMAGE_NT_HEADERS NtHeaders = RtlImageNtHeader(ImageBase);
    if (NtHeaders != nullptr && ReturnAddress >= (ULONG_PTR)ImageBase &&
        ReturnAddress < (ULONG_PTR)ImageBase + NtHeaders->OptionalHeader.SizeOfImage)
    {
        // Syscall return address within the exe file
        ReturnVal = (ULONG_PTR)(ULONG)STATUS_PORT_NOT_SET;

        // Uninstall ourselves after we have completed the sequence { NtQIP, NtQIP }. More NtSITs will follow but we can't do anything about them
        NumManualSyscalls++;
        if (NumManualSyscalls >= 2)
        {
            InstallInstrumentationCallbackHook(NtCurrentProcess, TRUE);
        }
    }

    InterlockedAnd(TlsGetInstrumentationCallbackDisabled(), 0);

    return ReturnVal;
}

static DWORD_PTR KiUserExceptionDispatcherAddress = 0;

#ifndef _WIN64
PVOID NTAPI HandleNativeCallInternal(DWORD eaxValue, DWORD ecxValue)
{
    for (ULONG i = 0; i < _countof(HookDllData.HookNative); i++)
    {
        if (HookDllData.HookNative[i].eaxValue == eaxValue)
        {
            if (HookDllData.HookNative[i].ecxValue)
            {
                if (HookDllData.HookNative[i].ecxValue == ecxValue)
                {
                    return HookDllData.HookNative[i].hookedFunction;
                }
            }
            else
            {
                return HookDllData.HookNative[i].hookedFunction;
            }
        }
    }

    return 0;
}
#endif

void NAKED NTAPI HookedNativeCallInternal()
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
#ifndef _WIN64
    __asm
    {
        PUSHAD
        PUSH ECX
        PUSH EAX
        CALL HandleNativeCallInternal
        cmp eax, 0
        je NoHook
        POPAD
        ADD ESP,4
        PUSH ECX
        PUSH EAX
        CALL HandleNativeCallInternal
        jmp eax
        NoHook:
        POPAD
        jmp HookDllData.NativeCallContinue
    }
#endif
}



//////////////////////////////////////////////////////////////
////////////////////// TIME FUNCTIONS ////////////////////////
//////////////////////////////////////////////////////////////

static DWORD OneTickCount = 0;

DWORD WINAPI HookedGetTickCount(void)
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    if (!OneTickCount)
    {
        OneTickCount = HookDllData.dGetTickCount();
    }
    else
    {
        OneTickCount++;
    }
    return OneTickCount;
}

ULONGLONG WINAPI HookedGetTickCount64(void) //yes we can use DWORD
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    if (!OneTickCount)
    {
        if (HookDllData.dGetTickCount)
        {
            OneTickCount = HookDllData.dGetTickCount();
        }
        else
        {
            OneTickCount = RtlGetTickCount();
        }
    }
    else
    {
        OneTickCount++;
    }
    return OneTickCount;
}

static SYSTEMTIME OneLocalTime = {0};
static SYSTEMTIME OneSystemTime = {0};

void WINAPI HookedGetLocalTime(LPSYSTEMTIME lpSystemTime)
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    if (!OneLocalTime.wYear)
    {
        RealGetLocalTime(&OneLocalTime);

        if (HookDllData.dGetSystemTime)
        {
            RealGetSystemTime(&OneSystemTime);
        }
    }
    else
    {
        IncreaseSystemTime(&OneLocalTime);

        if (HookDllData.dGetSystemTime)
        {
            IncreaseSystemTime(&OneSystemTime);
        }
    }

    if (lpSystemTime)
    {
        memcpy(lpSystemTime, &OneLocalTime, sizeof(SYSTEMTIME));
    }
}

void WINAPI HookedGetSystemTime(LPSYSTEMTIME lpSystemTime)
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    if (!OneSystemTime.wYear)
    {
        RealGetSystemTime(&OneSystemTime);

        if (HookDllData.dGetLocalTime)
        {
            RealGetLocalTime(&OneLocalTime);
        }
    }
    else
    {
        IncreaseSystemTime(&OneSystemTime);

        if (HookDllData.dGetLocalTime)
        {
            IncreaseSystemTime(&OneLocalTime);
        }
    }

    if (lpSystemTime)
    {
        memcpy(lpSystemTime, &OneSystemTime, sizeof(SYSTEMTIME));
    }
}

static LARGE_INTEGER OneNativeSysTime = {0};

//////////////////////////////////////////////////////////////
////////////////////// TIME FUNCTIONS ////////////////////////
//////////////////////////////////////////////////////////////


static BOOL isBlocked = FALSE;

//GetLastError() function might not change if a  debugger is present (it has never been the case that it is always set to zero).
DWORD WINAPI HookedOutputDebugStringA(LPCSTR lpOutputString) //Worst anti-debug ever
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    if (RtlNtMajorVersion() >= 6) // Vista or later
        return 0;

    NtCurrentTeb()->LastErrorValue = NtCurrentTeb()->LastErrorValue + 1; //change last error
    return 1; //WinXP EAX -> 1
}

void FilterHwndList(HWND * phwndFirst, PULONG pcHwndNeeded)
{
    for (UINT i = 0; i < *pcHwndNeeded; i++)
    {
        if (phwndFirst[i] != nullptr && IsWindowBad(phwndFirst[i]))
        {
            if (i == 0)
            {
                // Find the first HWND that belongs to a different process (i + 1, i + 2... may still be ours)
                for (UINT j = i + 1; j < *pcHwndNeeded; j++)
                {
                    if (phwndFirst[j] != nullptr && !IsWindowBad(phwndFirst[j]))
                    {
                        phwndFirst[i] = phwndFirst[j];
                        break;
                    }
                }
            }
            else
            {
                phwndFirst[i] = phwndFirst[i - 1]; //just override with previous
            }
        }
    }
}

void FilterHandleInfo(PSYSTEM_HANDLE_INFORMATION pHandleInfo, PULONG pReturnLengthAdjust)
{
    *pReturnLengthAdjust = 0;
    const ULONG TrueCount = pHandleInfo->NumberOfHandles;
    for (ULONG i = 0; i < TrueCount; ++i)
    {
        // TODO: protect processes by name too
        if ((HookDllData.EnableProtectProcessId == TRUE && (ULONG)(pHandleInfo->Handles[i].UniqueProcessId == HookDllData.dwProtectedProcessId)) &&
            IsObjectTypeBad(pHandleInfo->Handles[i].ObjectTypeIndex))
        {
            pHandleInfo->NumberOfHandles--;
            *pReturnLengthAdjust += sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO);
            for (ULONG j = i; j < TrueCount - 1; ++j)
            {
                pHandleInfo->Handles[j] = pHandleInfo->Handles[j + 1];
                RtlZeroMemory(&pHandleInfo->Handles[j + 1], sizeof(pHandleInfo->Handles[j + 1]));
            }
            i--;
        }
    }
}

void FilterHandleInfoEx(PSYSTEM_HANDLE_INFORMATION_EX pHandleInfoEx, PULONG pReturnLengthAdjust)
{
    *pReturnLengthAdjust = 0;
    const ULONG TrueCount = (ULONG)pHandleInfoEx->NumberOfHandles;
    for (ULONG i = 0; i < TrueCount; ++i)
    {
        // TODO: protect processes by name too
        if ((HookDllData.EnableProtectProcessId == TRUE && (ULONG)(pHandleInfoEx->Handles[i].UniqueProcessId == HookDllData.dwProtectedProcessId)) &&
            IsObjectTypeBad(pHandleInfoEx->Handles[i].ObjectTypeIndex))
        {
            pHandleInfoEx->NumberOfHandles--;
            *pReturnLengthAdjust += sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX);
            for (ULONG j = i; j < TrueCount - 1; ++j)
            {
                pHandleInfoEx->Handles[j] = pHandleInfoEx->Handles[j + 1];
                RtlZeroMemory(&pHandleInfoEx->Handles[j + 1], sizeof(pHandleInfoEx->Handles[j + 1]));
            }
            i--;
        }
    }
}

void FilterObjects(POBJECT_TYPES_INFORMATION pObjectTypes)
{
    POBJECT_TYPE_INFORMATION pObject = pObjectTypes->TypeInformation;
    for (ULONG i = 0; i < pObjectTypes->NumberOfTypes; i++)
    {
        FilterObject(pObject, true);

        pObject = (POBJECT_TYPE_INFORMATION)(((PCHAR)(pObject + 1) + ALIGN_UP(pObject->TypeName.MaximumLength, ULONG_PTR)));
    }
}

void FilterObject(POBJECT_TYPE_INFORMATION pObject, bool zeroTotal)
{
    UNICODE_STRING debugObjectName = RTL_CONSTANT_STRING(L"DebugObject");
    if (RtlEqualUnicodeString(&debugObjectName, &pObject->TypeName, FALSE))
    {
        // Subtract just one from both counts for our debugger, unless the query was a generic one for all object types
        pObject->TotalNumberOfObjects = zeroTotal || pObject->TotalNumberOfObjects == 0 ? 0 : pObject->TotalNumberOfObjects - 1;
        pObject->TotalNumberOfHandles = zeroTotal || pObject->TotalNumberOfHandles == 0 ? 0 : pObject->TotalNumberOfHandles - 1;
    }
}

void FakeCurrentParentProcessId(PSYSTEM_PROCESS_INFORMATION pInfo)
{
    while (true)
    {
        if (pInfo->UniqueProcessId == NtCurrentTeb()->ClientId.UniqueProcess)
        {
            pInfo->InheritedFromUniqueProcessId = ULongToHandle(GetExplorerProcessId());
            break;
        }

        if (pInfo->NextEntryOffset == 0)
            break;

        pInfo = (PSYSTEM_PROCESS_INFORMATION)((DWORD_PTR)pInfo + pInfo->NextEntryOffset);
    }
}

void FakeCurrentOtherOperationCount(PSYSTEM_PROCESS_INFORMATION pInfo)
{
    while (true)
    {
        if (pInfo->UniqueProcessId == NtCurrentTeb()->ClientId.UniqueProcess)
        {
            LARGE_INTEGER one;
            one.QuadPart = 1;
            pInfo->OtherOperationCount = one;
            break;
        }

        if (pInfo->NextEntryOffset == 0)
            break;

        pInfo = (PSYSTEM_PROCESS_INFORMATION)((DWORD_PTR)pInfo + pInfo->NextEntryOffset);
    }
}

void FilterProcess(PSYSTEM_PROCESS_INFORMATION pInfo)
{
    PSYSTEM_PROCESS_INFORMATION pPrev = pInfo;

    while (TRUE)
    {
        if (IsProcessNameBad(&pInfo->ImageName) || ((HookDllData.EnableProtectProcessId == TRUE) && (HandleToULong(pInfo->UniqueProcessId) == HookDllData.dwProtectedProcessId)))
        {
            if (pInfo->ImageName.Buffer)
                ZeroMemory(pInfo->ImageName.Buffer, pInfo->ImageName.Length);

            if (pInfo->NextEntryOffset == 0) //last element
            {
                pPrev->NextEntryOffset = 0;
            }
            else
            {
                pPrev->NextEntryOffset += pInfo->NextEntryOffset;
            }
        }
        else
        {
            pPrev = pInfo;
        }

        if (pInfo->NextEntryOffset == 0)
        {
            break;
        }
        else
        {
            pInfo = (PSYSTEM_PROCESS_INFORMATION)((DWORD_PTR)pInfo + pInfo->NextEntryOffset);
        }
    }
}
