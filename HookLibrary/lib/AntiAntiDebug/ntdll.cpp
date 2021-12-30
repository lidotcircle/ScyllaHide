#include <Windows.h>
#include "exchange_data.h"
#include "hook_main.h"
#include "hook_helper.h"
#include "hook_log_client.h"
#include "Tls.h"


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


DLLExport_C NTSTATUS NTAPI HookedNtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength)
{
    if (ThreadInformationClass == ThreadHideFromDebugger && ThreadInformationLength == 0) // NB: ThreadInformation is not checked, this is deliberate
    {
        if (ThreadHandle == NtCurrentThread ||
            HandleToULong(NtCurrentTeb()->ClientId.UniqueProcess) == GetProcessIdByThreadHandle(ThreadHandle)) //thread inside this process?
        {
            return STATUS_SUCCESS;
        }
    }

    auto dNtSetInformationThread = exchange_data.lookup_trampoline<decltype(&NtSetInformationThread)>(&NtSetInformationThread);
    return dNtSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
}


static void FakeCurrentParentProcessId(PSYSTEM_PROCESS_INFORMATION pInfo)
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

static void FakeCurrentOtherOperationCount(PSYSTEM_PROCESS_INFORMATION pInfo)
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

static void FilterProcess(PSYSTEM_PROCESS_INFORMATION pInfo)
{
    PSYSTEM_PROCESS_INFORMATION pPrev = pInfo;

    while (TRUE)
    {
        // TODO || ((HookDllData.EnableProtectProcessId == TRUE) && (HandleToULong(pInfo->UniqueProcessId) == HookDllData.dwProtectedProcessId))
        if (IsProcessNameBad(&pInfo->ImageName))
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

static void FilterHandleInfo(PSYSTEM_HANDLE_INFORMATION pHandleInfo, PULONG pReturnLengthAdjust)
{
    *pReturnLengthAdjust = 0;
    const ULONG TrueCount = pHandleInfo->NumberOfHandles;
    for (ULONG i = 0; i < TrueCount; ++i)
    {
        // TODO: protect processes by name too
        // (HookDllData.EnableProtectProcessId == TRUE && (ULONG)(pHandleInfo->Handles[i].UniqueProcessId == HookDllData.dwProtectedProcessId))
        if (IsObjectTypeBad(pHandleInfo->Handles[i].ObjectTypeIndex))
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

static void FilterHandleInfoEx(PSYSTEM_HANDLE_INFORMATION_EX pHandleInfoEx, PULONG pReturnLengthAdjust)
{
    *pReturnLengthAdjust = 0;
    const ULONG TrueCount = (ULONG)pHandleInfoEx->NumberOfHandles;
    for (ULONG i = 0; i < TrueCount; ++i)
    {
        // TODO: protect processes by name too
        // (HookDllData.EnableProtectProcessId == TRUE && (ULONG)(pHandleInfoEx->Handles[i].UniqueProcessId == HookDllData.dwProtectedProcessId))
        if (IsObjectTypeBad(pHandleInfoEx->Handles[i].ObjectTypeIndex))
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

DLLExport_C NTSTATUS NTAPI HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
    auto dNtQuerySystemInformation = exchange_data.lookup_trampoline<decltype(&NtQuerySystemInformation)>(&NtQuerySystemInformation);
    NTSTATUS ntStat = dNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
    if (!NT_SUCCESS(ntStat))
        return ntStat;

    BACKUP_RETURNLENGTH();
    switch (SystemInformationClass)
    {
        case SystemKernelDebuggerInformation: {
            ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation)->KernelDebuggerEnabled = FALSE;
            ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation)->KernelDebuggerNotPresent = TRUE;
        } break;
        case SystemProcessInformation:
        case SystemExtendedProcessInformation: 
        case SystemSessionProcessInformation: {
            PSYSTEM_PROCESS_INFORMATION ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
            if (SystemInformationClass == SystemSessionProcessInformation)
                ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((PSYSTEM_SESSION_PROCESS_INFORMATION)SystemInformation)->Buffer;

            FilterProcess(ProcessInfo);
            FakeCurrentParentProcessId(ProcessInfo);
            FakeCurrentOtherOperationCount(ProcessInfo);
        } break;
        case SystemHandleInformation: {
            ULONG ReturnLengthAdjust = 0;

            FilterHandleInfo((PSYSTEM_HANDLE_INFORMATION)SystemInformation, &ReturnLengthAdjust);

            if (ReturnLengthAdjust <= TempReturnLength)
                TempReturnLength -= ReturnLengthAdjust;
        } break;
        case SystemExtendedHandleInformation: {
            ULONG ReturnLengthAdjust = 0;

            FilterHandleInfoEx((PSYSTEM_HANDLE_INFORMATION_EX)SystemInformation, &ReturnLengthAdjust);

            if (ReturnLengthAdjust <= TempReturnLength)
                TempReturnLength -= ReturnLengthAdjust;
       } break;
       case SystemCodeIntegrityInformation: {
            ((PSYSTEM_CODEINTEGRITY_INFORMATION)SystemInformation)->CodeIntegrityOptions = CODEINTEGRITY_OPTION_ENABLED;
       } break;
       case SystemKernelDebuggerInformationEx: {
            ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation)->DebuggerAllowed = FALSE;
            ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation)->DebuggerEnabled = FALSE;
            ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation)->DebuggerPresent = FALSE;
       } break;
       case SystemKernelDebuggerFlags: {
            *(PUCHAR)SystemInformation = 0;
       } break;
       case SystemCodeIntegrityUnlockInformation: {
            RtlZeroMemory(SystemInformation, SystemInformationLength);
       } break;
    }
    RESTORE_RETURNLENGTH();

    return STATUS_SUCCESS;
}


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


DLLExport_C NTSTATUS NTAPI HookedNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
{
    if (NumManualSyscalls == 0 &&
        InterlockedOr(&InstrumentationCallbackHookInstalled, 0x1) == 0)
    {
        InstallInstrumentationCallbackHook(NtCurrentProcess, FALSE);
    }
    auto dNtQueryInformationProcess = 
        exchange_data.lookup_trampoline<decltype(&NtQueryInformationProcess)>(&NtQueryInformationProcess);

    NTSTATUS Status;
    if (ProcessInformationClass == ProcessDebugObjectHandle && // Handle ProcessDebugObjectHandle early
        ProcessInformation != nullptr &&
        ProcessInformationLength == sizeof(HANDLE) &&
        (ProcessHandle == NtCurrentProcess || HandleToULong(NtCurrentTeb()->ClientId.UniqueProcess) == GetProcessIdByProcessHandle(ProcessHandle)))
    {
        // Verify (1) that the handle has PROCESS_QUERY_INFORMATION access, and (2) that writing
        // to ProcessInformation and/or ReturnLength does not cause any access or alignment violations
        Status = dNtQueryInformationProcess(ProcessHandle,
                                            ProcessDebugPort, // Note: not ProcessDebugObjectHandle
                                            ProcessInformation,
                                            sizeof(HANDLE),
                                            ReturnLength);
        if (!NT_SUCCESS(Status))
            return Status;

        // The kernel calls DbgkOpenProcessDebugPort here

        // This should be done in a try/except block, but since we are a mapped DLL we cannot use SEH.
        // Rely on the fact that the NtQIP call we just did wrote to the same buffers successfully
        *(PHANDLE)ProcessInformation = nullptr;
        if (ReturnLength != nullptr)
            *ReturnLength = sizeof(HANDLE);

        return STATUS_PORT_NOT_SET;
    }

    if ((ProcessInformationClass == ProcessDebugFlags ||
        ProcessInformationClass == ProcessDebugPort ||
        ProcessInformationClass == ProcessBasicInformation ||
        ProcessInformationClass == ProcessBreakOnTermination ||
        ProcessInformationClass == ProcessHandleTracing ||
        ProcessInformationClass == ProcessIoCounters) &&
        (ProcessHandle == NtCurrentProcess || HandleToULong(NtCurrentTeb()->ClientId.UniqueProcess) == GetProcessIdByProcessHandle(ProcessHandle)))
    {
        Status = dNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);

        if (!NT_SUCCESS(Status) || ProcessInformation == nullptr || ProcessInformationLength == 0)
            return Status;

        if (ProcessInformationClass == ProcessDebugFlags)
        {
            BACKUP_RETURNLENGTH();

            *((ULONG *)ProcessInformation) = ((ValueProcessDebugFlags & PROCESS_NO_DEBUG_INHERIT) != 0) ? 0 : PROCESS_DEBUG_INHERIT;

            RESTORE_RETURNLENGTH();
        }
        else if (ProcessInformationClass == ProcessDebugPort)
        {
            BACKUP_RETURNLENGTH();

            *((HANDLE *)ProcessInformation) = nullptr;

            RESTORE_RETURNLENGTH();
        }
        else if (ProcessInformationClass == ProcessBasicInformation) //Fake parent
        {
            BACKUP_RETURNLENGTH();

            ((PPROCESS_BASIC_INFORMATION)ProcessInformation)->InheritedFromUniqueProcessId = ULongToHandle(GetExplorerProcessId());

            RESTORE_RETURNLENGTH();
        }
        else if (ProcessInformationClass == ProcessBreakOnTermination)
        {
            BACKUP_RETURNLENGTH();

            *((ULONG *)ProcessInformation) = ValueProcessBreakOnTermination;

            RESTORE_RETURNLENGTH();
        }
        else if (ProcessInformationClass == ProcessHandleTracing)
        {
            BACKUP_RETURNLENGTH();
            RESTORE_RETURNLENGTH(); // Trigger any possible exceptions caused by messing with the output buffer before changing the final return status

            Status = IsProcessHandleTracingEnabled ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
        }
        else if (ProcessInformationClass == ProcessIoCounters)
        {
            BACKUP_RETURNLENGTH();

            ((PIO_COUNTERS)ProcessInformation)->OtherOperationCount = 1;

            RESTORE_RETURNLENGTH();
        }

        return Status;
    }

    return dNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}


DLLExport_C NTSTATUS NTAPI HookedNtSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength)
{
    auto dNtSetInformationProcess = 
        exchange_data.lookup_trampoline<decltype(&NtSetInformationProcess)>(&NtSetInformationProcess);
    if (ProcessHandle == NtCurrentProcess || HandleToULong(NtCurrentTeb()->ClientId.UniqueProcess) == GetProcessIdByProcessHandle(ProcessHandle))
    {
        if (ProcessInformationClass == ProcessBreakOnTermination)
        {
            if (ProcessInformationLength != sizeof(ULONG))
            {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            // NtSetInformationProcess will happily dereference this pointer
            if (ProcessInformation == NULL)
            {
                return STATUS_ACCESS_VIOLATION;
            }

            // A process must have debug privileges enabled to set the ProcessBreakOnTermination flag
            if (!HasDebugPrivileges(NtCurrentProcess))
            {
                return STATUS_PRIVILEGE_NOT_HELD;
            }

            ValueProcessBreakOnTermination = *((ULONG *)ProcessInformation);
            return STATUS_SUCCESS;
        }

        // Don't allow changing the debug inherit flag, and keep track of the new value to report in NtQIP
        if (ProcessInformationClass == ProcessDebugFlags)
        {
            if (ProcessInformationLength != sizeof(ULONG))
            {
                return STATUS_INFO_LENGTH_MISMATCH;
            }

            if (ProcessInformation == NULL)
            {
                return STATUS_ACCESS_VIOLATION;
            }

            ULONG Flags = *(ULONG*)ProcessInformation;
            if ((Flags & ~PROCESS_DEBUG_INHERIT) != 0)
            {
                return STATUS_INVALID_PARAMETER;
            }

            if ((Flags & PROCESS_DEBUG_INHERIT) != 0)
            {
                ValueProcessDebugFlags &= ~PROCESS_NO_DEBUG_INHERIT;
            }
            else
            {
                ValueProcessDebugFlags |= PROCESS_NO_DEBUG_INHERIT;
            }
            return STATUS_SUCCESS;
        }

        //PROCESS_HANDLE_TRACING_ENABLE -> ULONG, PROCESS_HANDLE_TRACING_ENABLE_EX -> ULONG,ULONG
        if (ProcessInformationClass == ProcessHandleTracing)
        {
            bool enable = ProcessInformationLength != 0; // A length of 0 is valid and indicates we should disable tracing
            if (enable)
            {
                if (ProcessInformationLength != sizeof(ULONG) && ProcessInformationLength != (sizeof(ULONG) * 2))
                {
                    return STATUS_INFO_LENGTH_MISMATCH;
                }

                // NtSetInformationProcess will happily dereference this pointer
                if (ProcessInformation == NULL)
                {
                    return STATUS_ACCESS_VIOLATION;
                }

                PPROCESS_HANDLE_TRACING_ENABLE_EX phtEx = (PPROCESS_HANDLE_TRACING_ENABLE_EX)ProcessInformation;
                if (phtEx->Flags != 0)
                {
                    return STATUS_INVALID_PARAMETER;
                }
            }

            IsProcessHandleTracingEnabled = enable;
            return STATUS_SUCCESS;
        }
    }
    return dNtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
}


static void FilterObject(POBJECT_TYPE_INFORMATION pObject, bool zeroTotal)
{
    UNICODE_STRING debugObjectName = RTL_CONSTANT_STRING(L"DebugObject");
    if (RtlEqualUnicodeString(&debugObjectName, &pObject->TypeName, FALSE))
    {
        // Subtract just one from both counts for our debugger, unless the query was a generic one for all object types
        pObject->TotalNumberOfObjects = zeroTotal || pObject->TotalNumberOfObjects == 0 ? 0 : pObject->TotalNumberOfObjects - 1;
        pObject->TotalNumberOfHandles = zeroTotal || pObject->TotalNumberOfHandles == 0 ? 0 : pObject->TotalNumberOfHandles - 1;
    }
}

static void FilterObjects(POBJECT_TYPES_INFORMATION pObjectTypes)
{
    POBJECT_TYPE_INFORMATION pObject = pObjectTypes->TypeInformation;
    for (ULONG i = 0; i < pObjectTypes->NumberOfTypes; i++)
    {
        FilterObject(pObject, true);

        pObject = (POBJECT_TYPE_INFORMATION)(((PCHAR)(pObject + 1) + ALIGN_UP(pObject->TypeName.MaximumLength, ULONG_PTR)));
    }
}

DLLExport_C NTSTATUS NTAPI HookedNtQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength)
{
    auto dNtQueryObject = 
        exchange_data.lookup_trampoline<decltype(&NtQueryObject)>(&NtQueryObject);
    NTSTATUS ntStat = dNtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);

    BACKUP_RETURNLENGTH();
    if ((ObjectInformationClass == ObjectTypesInformation ||
        ObjectInformationClass == ObjectTypeInformation) &&
        (NT_SUCCESS(ntStat) && ObjectInformation))
    {
        if (ObjectInformationClass == ObjectTypesInformation)
        {
            FilterObjects((POBJECT_TYPES_INFORMATION)ObjectInformation);
        }
        else if (ObjectInformationClass == ObjectTypeInformation)
        {
            FilterObject((POBJECT_TYPE_INFORMATION)ObjectInformation, false);
        }
    }
    RESTORE_RETURNLENGTH();

    return ntStat;
}


DLLExport_C NTSTATUS NTAPI HookedNtYieldExecution()
{
    auto dNtYieldExecution = 
        exchange_data.lookup_trampoline<decltype(&NtYieldExecution)>(&NtYieldExecution);
    NTSTATUS ntStat = dNtYieldExecution();
    return STATUS_ACCESS_DENIED; //better than STATUS_SUCCESS or STATUS_NO_YIELD_PERFORMED
}


DLLExport_C NTSTATUS NTAPI HookedNtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
{
    DWORD ContextBackup = 0;
    BOOLEAN DebugRegistersRequested = FALSE;
    if (ThreadHandle == NtCurrentThread ||
        HandleToULong(NtCurrentTeb()->ClientId.UniqueProcess) == GetProcessIdByThreadHandle(ThreadHandle)) //thread inside this process?
    {
        if (ThreadContext)
        {
            ContextBackup = ThreadContext->ContextFlags;
            ThreadContext->ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;
            DebugRegistersRequested = ThreadContext->ContextFlags != ContextBackup;
        }
    }

    auto dNtGetContextThread = 
        exchange_data.lookup_trampoline<decltype(&NtGetContextThread)>(&NtGetContextThread);
    NTSTATUS ntStat = dNtGetContextThread(ThreadHandle, ThreadContext);

    if (ContextBackup)
    {
        ThreadContext->ContextFlags = ContextBackup;
        if (DebugRegistersRequested)
        {
            ThreadContext->Dr0 = 0;
            ThreadContext->Dr1 = 0;
            ThreadContext->Dr2 = 0;
            ThreadContext->Dr3 = 0;
            ThreadContext->Dr6 = 0;
            ThreadContext->Dr7 = 0;
#ifdef _WIN64
            ThreadContext->LastBranchToRip = 0;
            ThreadContext->LastBranchFromRip = 0;
            ThreadContext->LastExceptionToRip = 0;
            ThreadContext->LastExceptionFromRip = 0;
#endif
        }
    }
    return ntStat;
}


DLLExport_C NTSTATUS NTAPI HookedNtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
{
    DWORD ContextBackup = 0;
    if (ThreadHandle == NtCurrentThread ||
        HandleToULong(NtCurrentTeb()->ClientId.UniqueProcess) == GetProcessIdByThreadHandle(ThreadHandle)) //thread inside this process?
    {
        if (ThreadContext)
        {
            ContextBackup = ThreadContext->ContextFlags;
            ThreadContext->ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;
        }
    }

    auto dNtSetContextThread = 
        exchange_data.lookup_trampoline<decltype(&NtSetContextThread)>(&NtSetContextThread);
    NTSTATUS ntStat = dNtSetContextThread(ThreadHandle, ThreadContext);

    if (ContextBackup)
    {
        ThreadContext->ContextFlags = ContextBackup;
    }

    return ntStat;
}


static SAVE_DEBUG_REGISTERS ArrayDebugRegister[100] = { 0 }; //Max 100 threads
static void ThreadDebugContextRemoveEntry(const int index)
{
    ArrayDebugRegister[index].dwThreadId = 0;
}

static void ThreadDebugContextSaveContext(const int index, const PCONTEXT ThreadContext)
{
    ArrayDebugRegister[index].dwThreadId = HandleToULong(NtCurrentTeb()->ClientId.UniqueThread);
    ArrayDebugRegister[index].Dr0 = ThreadContext->Dr0;
    ArrayDebugRegister[index].Dr1 = ThreadContext->Dr1;
    ArrayDebugRegister[index].Dr2 = ThreadContext->Dr2;
    ArrayDebugRegister[index].Dr3 = ThreadContext->Dr3;
    ArrayDebugRegister[index].Dr6 = ThreadContext->Dr6;
    ArrayDebugRegister[index].Dr7 = ThreadContext->Dr7;
}

static int ThreadDebugContextFindExistingSlotIndex()
{
    for (int i = 0; i < _countof(ArrayDebugRegister); i++)
    {
        if (ArrayDebugRegister[i].dwThreadId != 0)
        {
            if (ArrayDebugRegister[i].dwThreadId == HandleToULong(NtCurrentTeb()->ClientId.UniqueThread))
            {
                return i;
            }
        }
    }

    return -1;
}

static int ThreadDebugContextFindFreeSlotIndex()
{
    for (int i = 0; i < _countof(ArrayDebugRegister); i++)
    {
        if (ArrayDebugRegister[i].dwThreadId == 0)
        {
            return i;
        }
    }

    return -1;
}


void NTAPI HandleKiUserExceptionDispatcher(PEXCEPTION_RECORD pExcptRec, PCONTEXT ContextFrame)
{
    if (ContextFrame && (ContextFrame->ContextFlags & CONTEXT_DEBUG_REGISTERS))
    {
        int slotIndex = ThreadDebugContextFindFreeSlotIndex();
        if (slotIndex != -1)
        {
            ThreadDebugContextSaveContext(slotIndex, ContextFrame);
        }

        ContextFrame->Dr0 = 0;
        ContextFrame->Dr1 = 0;
        ContextFrame->Dr2 = 0;
        ContextFrame->Dr3 = 0;
        ContextFrame->Dr6 = 0;
        ContextFrame->Dr7 = 0;
    }
}

#ifdef _WIN64
DLLExport_C void NTAPI HookedKiUserExceptionDispatcher()
{
    // inline assembly is not supported in x86_64 with CL.  a more elegant
    // way to do this would be to modify the project to include an .asm
    // source file that defines 'HookedKiUserExceptionDispatcher' for both
    // 32 and 64 bit.
    // the + 8 in the line below is because we arrive at this function via
    // a CALL instruction which causes the stack to shift.  This CALL in
    // the trampoline is necessary because HandleKiUserExceptionDispatcher
    // will end in a RET instruction, and the CALL preserves the stack.
    PCONTEXT ContextFrame = (PCONTEXT)(((UINT_PTR)_AddressOfReturnAddress()) + 8);

    HandleKiUserExceptionDispatcher(nullptr, ContextFrame);
}
#else
DLLExport_C NAKED VOID NTAPI HookedKiUserExceptionDispatcher() // (PEXCEPTION_RECORD pExcptRec, PCONTEXT ContextFrame) //remove DRx Registers
{
    //MOV ECX,DWORD PTR SS:[ESP+4] <- ContextFrame
    //MOV EBX,DWORD PTR SS:[ESP] <- pExcptRec
    __asm
    {
        MOV EAX, [ESP + 4]
        MOV ECX, [ESP]
        PUSH EAX
        PUSH ECX
        CALL HandleKiUserExceptionDispatcher
    }

    void* dKiUserExceptionDispatcher;
    dKiUserExceptionDispatcher = exchange_data.lookup_trampoline("KiUserExceptionDispatcher");

    __asm
    {
        MOV EAX, dKiUserExceptionDispatcher
        JMP EAX
    }
}
#endif

static DWORD_PTR KiUserExceptionDispatcherAddress = 0;
DLLExport_C NTSTATUS NTAPI HookedNtContinue(PCONTEXT ThreadContext, BOOLEAN RaiseAlert) //restore DRx Registers
{
    DWORD_PTR retAddress = (DWORD_PTR)_ReturnAddress();
    if (!KiUserExceptionDispatcherAddress)
    {
        UNICODE_STRING NtdllName = RTL_CONSTANT_STRING(L"ntdll.dll");
        PVOID Ntdll;
        if (NT_SUCCESS(LdrGetDllHandle(nullptr, nullptr, &NtdllName, &Ntdll)))
        {
            ANSI_STRING KiUserExceptionDispatcherName = RTL_CONSTANT_ANSI_STRING("KiUserExceptionDispatcher");
            LdrGetProcedureAddress(Ntdll, &KiUserExceptionDispatcherName, 0, (PVOID*)&KiUserExceptionDispatcherAddress);
        }
    }

    if (ThreadContext != nullptr &&
        retAddress >= KiUserExceptionDispatcherAddress && retAddress < (KiUserExceptionDispatcherAddress + 0x100))
    {
        int index = ThreadDebugContextFindExistingSlotIndex();
        if (index != -1)
        {
            ThreadContext->Dr0 = ArrayDebugRegister[index].Dr0;
            ThreadContext->Dr1 = ArrayDebugRegister[index].Dr1;
            ThreadContext->Dr2 = ArrayDebugRegister[index].Dr2;
            ThreadContext->Dr3 = ArrayDebugRegister[index].Dr3;
            ThreadContext->Dr6 = ArrayDebugRegister[index].Dr6;
            ThreadContext->Dr7 = ArrayDebugRegister[index].Dr7;
            ThreadDebugContextRemoveEntry(index);
        }
    }

    auto dNtContinue = 
        exchange_data.lookup_trampoline<decltype(&NtContinue)>(&NtContinue);
    return dNtContinue(ThreadContext, RaiseAlert);
}


DLLExport_C NTSTATUS NTAPI HookedNtClose(HANDLE Handle)
{
    OBJECT_HANDLE_FLAG_INFORMATION flags;
    NTSTATUS Status;
    auto dNtQueryObject = 
        exchange_data.lookup_trampoline<decltype(&NtQueryObject)>(&NtQueryObject);

    if (dNtQueryObject != nullptr)
        Status = dNtQueryObject(Handle, ObjectHandleFlagInformation, &flags, sizeof(OBJECT_HANDLE_FLAG_INFORMATION), nullptr);
    else
        Status = NtQueryObject(Handle, ObjectHandleFlagInformation, &flags, sizeof(OBJECT_HANDLE_FLAG_INFORMATION), nullptr);

    if (NT_SUCCESS(Status))
    {
        if (flags.ProtectFromClose)
        {
            return STATUS_HANDLE_NOT_CLOSABLE;
        }

        auto dNtClose = exchange_data.lookup_trampoline<decltype(&NtClose)>(&NtClose);
        return dNtClose(Handle);
    }

    return STATUS_INVALID_HANDLE;
}


DLLExport_C NTSTATUS NTAPI HookedNtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options)
{
    if (Options & DUPLICATE_CLOSE_SOURCE)
    {
        // If a process is being debugged and duplicates a handle with DUPLICATE_CLOSE_SOURCE, *and* the handle has the ProtectFromClose bit set, a STATUS_HANDLE_NOT_CLOSABLE exception will occur.
        // This is actually the exact same exception we already check for in NtClose, but the difference is that this NtClose call happens inside the kernel which we obviously can't hook.
        // When a process is not being debugged, NtDuplicateObject will simply return success without closing the source. This is because ObDuplicateObject ignores NtClose return values
        OBJECT_HANDLE_FLAG_INFORMATION HandleFlags;
        NTSTATUS Status;
        auto dNtQueryObject = 
            exchange_data.lookup_trampoline<decltype(&NtQueryObject)>(&NtQueryObject);
        if (dNtQueryObject != nullptr)
            Status = dNtQueryObject(SourceHandle, ObjectHandleFlagInformation, &HandleFlags, sizeof(HandleFlags), nullptr);
        else
            Status = NtQueryObject(SourceHandle, ObjectHandleFlagInformation, &HandleFlags, sizeof(HandleFlags), nullptr);

        if (NT_SUCCESS(Status) && HandleFlags.ProtectFromClose)
        {
            // Prevent the exception
            Options &= ~DUPLICATE_CLOSE_SOURCE;
        }
    }

    auto dNtDuplicateObject =
        exchange_data.lookup_trampoline<decltype(&NtDuplicateObject)>(&NtDuplicateObject);
    return dNtDuplicateObject(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
}


static LARGE_INTEGER OneNativeSysTime = {0};
DLLExport_C NTSTATUS WINAPI HookedNtQuerySystemTime(PLARGE_INTEGER SystemTime)
{
    if (!OneNativeSysTime.QuadPart)
    {
        auto dNtQuerySystemTime = 
            exchange_data.lookup_trampoline<decltype(&NtQuerySystemTime)>(&NtQuerySystemTime);
        dNtQuerySystemTime(&OneNativeSysTime);
    }
    else
    {
        OneNativeSysTime.QuadPart++;
    }

    auto dNtQuerySystemTime =
        exchange_data.lookup_trampoline<decltype(&NtQuerySystemTime)>(&NtQuerySystemTime);
    NTSTATUS ntStat = dNtQuerySystemTime(SystemTime);

    if (ntStat == STATUS_SUCCESS)
    {
        if (SystemTime)
        {
            SystemTime->QuadPart = OneNativeSysTime.QuadPart;
        }
    }

    return ntStat;
}


static LARGE_INTEGER OnePerformanceCounter = {0};
static LARGE_INTEGER OnePerformanceFrequency = {0};

DLLExport_C NTSTATUS NTAPI HookedNtQueryPerformanceCounter(PLARGE_INTEGER PerformanceCounter, PLARGE_INTEGER PerformanceFrequency)
{
    auto dNtQueryPerformanceCounter =
        exchange_data.lookup_trampoline<decltype(&NtQueryPerformanceCounter)>(&NtQueryPerformanceCounter);
    if (!OnePerformanceCounter.QuadPart)
    {
        dNtQueryPerformanceCounter(&OnePerformanceCounter, &OnePerformanceFrequency);
    }
    else
    {
        OnePerformanceCounter.QuadPart++;
    }

    NTSTATUS ntStat = dNtQueryPerformanceCounter(PerformanceCounter, PerformanceFrequency);

    if (ntStat == STATUS_SUCCESS)
    {
        if (PerformanceFrequency) //OPTIONAL
        {
            PerformanceFrequency->QuadPart = OnePerformanceFrequency.QuadPart;
        }

        if (PerformanceCounter)
        {
            PerformanceCounter->QuadPart = OnePerformanceCounter.QuadPart;
        }
    }

    return ntStat;
}


static BOOL isBlocked = FALSE;
DLLExport_C BOOL NTAPI HookedNtUserBlockInput(BOOL fBlockIt)
{
    if (isBlocked == FALSE && fBlockIt != FALSE)
    {
        isBlocked = TRUE;
        return TRUE;
    }
    else if (isBlocked != FALSE && fBlockIt == FALSE)
    {
        isBlocked = FALSE;
        return TRUE;
    }

    return FALSE;
}


DLLExport_C HANDLE NTAPI HookedNtUserQueryWindow(HWND hwnd, WINDOWINFOCLASS WindowInfo)
{
    if ((WindowInfo == WindowProcess || WindowInfo == WindowThread) && IsWindowBad(hwnd))
    {
        if (WindowInfo == WindowProcess)
            return NtCurrentTeb()->ClientId.UniqueProcess;
        if (WindowInfo == WindowThread)
            return NtCurrentTeb()->ClientId.UniqueThread;
    }
    auto dNtUserQueryWindow =
        exchange_data.lookup_trampoline<decltype(&HookedNtUserQueryWindow)>("NtUserQueryWindow");
    return dNtUserQueryWindow(hwnd, WindowInfo);
}



DLLExport_C HWND NTAPI HookedNtUserFindWindowEx(HWND hWndParent, HWND hWndChildAfter, PUNICODE_STRING lpszClass, PUNICODE_STRING lpszWindow, DWORD dwType)
{
    auto dNtUserFindWindowEx =
        exchange_data.lookup_trampoline<decltype(&HookedNtUserFindWindowEx)>("NtUserFindWindowEx");
    HWND resultHwnd = dNtUserFindWindowEx(hWndParent, hWndChildAfter, lpszClass, lpszWindow, dwType);
    if (resultHwnd)
    {
        if (IsWindowClassNameBad(lpszClass) || IsWindowNameBad(lpszWindow))
        {
            return 0;
        }

        auto dNtUserQueryWindow =
            exchange_data.lookup_trampoline<decltype(&HookedNtUserQueryWindow)>("NtUserQueryWindow");

        auto enableProtecteProcessId =
            exchange_data.lookup_key("EnableProtecteProcessId");
        if (enableProtecteProcessId)
        {
            DWORD dwProcessId;
            if (dNtUserQueryWindow)
            {
                dwProcessId = HandleToULong(dNtUserQueryWindow(resultHwnd, WindowProcess));
            }
            else
            {
                dwProcessId = HandleToULong(HookedNtUserQueryWindow(resultHwnd, WindowProcess));
            }

            auto protecteProcessId =
                exchange_data.lookup_key("ProtecteProcessId");
            // TODO
            if (protecteProcessId)
            {
                return 0;
            }
        }
    }
    return resultHwnd;
}


DLLExport_C NTSTATUS NTAPI HookedNtSetDebugFilterState(ULONG ComponentId, ULONG Level, BOOLEAN State)
{
    return HasDebugPrivileges(NtCurrentProcess) ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
}


static void FilterHwndList(HWND * phwndFirst, PULONG pcHwndNeeded)
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

DLLExport_C NTSTATUS NTAPI HookedNtUserBuildHwndList(HDESK hDesktop, HWND hwndParent, BOOLEAN bChildren, ULONG dwThreadId, ULONG lParam, HWND* pWnd, PULONG pBufSize)
{
    auto dNtUserBuildHwndList =
        exchange_data.lookup_trampoline<decltype(&HookedNtUserBuildHwndList)>("NtUserBuildHwndList");
    NTSTATUS ntStat = dNtUserBuildHwndList(hDesktop, hwndParent, bChildren, dwThreadId, lParam, pWnd, pBufSize);

    if (NT_SUCCESS(ntStat) && pWnd != nullptr && pBufSize != nullptr)
    {
        FilterHwndList(pWnd, pBufSize);
    }

    return ntStat;
}


DLLExport_C NTSTATUS NTAPI HookedNtUserBuildHwndList_Eight(HDESK hDesktop, HWND hwndParent, BOOLEAN bChildren, BOOLEAN bUnknownFlag, ULONG dwThreadId, ULONG lParam, HWND* pWnd, PULONG pBufSize)
{
    auto dNtUserBuildHwndList =
        exchange_data.lookup_trampoline<decltype(&HookedNtUserBuildHwndList)>("NtUserBuildHwndList");
    NTSTATUS ntStat = ((t_NtUserBuildHwndList_Eight)dNtUserBuildHwndList)(hDesktop, hwndParent, bChildren, bUnknownFlag, dwThreadId, lParam, pWnd, pBufSize);

    if (NT_SUCCESS(ntStat) && pWnd != nullptr && pBufSize != nullptr)
    {
        FilterHwndList(pWnd, pBufSize);
    }

    return ntStat;
}


DLLExport_C HWND NTAPI HookedNtUserGetForegroundWindow()
{
    auto dNtUserGetForegroundWindow =
        exchange_data.lookup_trampoline<decltype(&HookedNtUserGetForegroundWindow)>("NtUserGetForegroundWindow");
    HWND Hwnd = dNtUserGetForegroundWindow();
    if (Hwnd != nullptr && IsWindowBad(Hwnd))
    {
        // TODO
        // Hwnd = (HWND)NtUserGetThreadState(THREADSTATE_ACTIVEWINDOW);
    }
    return Hwnd;
}


//WIN XP: CreateThread -> CreateRemoteThread -> NtCreateThread
DLLExport_C NTSTATUS NTAPI HookedNtCreateThread(PHANDLE ThreadHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,HANDLE ProcessHandle,PCLIENT_ID ClientId,PCONTEXT ThreadContext,PINITIAL_TEB InitialTeb,BOOLEAN CreateSuspended)
{
    if (ProcessHandle == NtCurrentProcess)
    {
        return STATUS_INSUFFICIENT_RESOURCES;//STATUS_INVALID_PARAMETER STATUS_INVALID_HANDLE STATUS_INSUFFICIENT_RESOURCES
    }
    auto dNtCreateThread =
        exchange_data.lookup_trampoline<decltype(&NtCreateThread)>(&NtCreateThread);
    return dNtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId,ThreadContext, InitialTeb,CreateSuspended);
}

//WIN 7: CreateThread -> CreateRemoteThreadEx -> NtCreateThreadEx
DLLExport_C NTSTATUS NTAPI HookedNtCreateThreadEx(PHANDLE ThreadHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,HANDLE ProcessHandle,PUSER_THREAD_START_ROUTINE StartRoutine,PVOID Argument,ULONG CreateFlags,ULONG_PTR ZeroBits,SIZE_T StackSize,SIZE_T MaximumStackSize,PPS_ATTRIBUTE_LIST AttributeList)
{
    auto preventHideFromDebugger =
        exchange_data.lookup_key("PreventHideFromDebugger");
    if (preventHideFromDebugger) //prevent hide from debugger
    {
        if (CreateFlags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER)
        {
            CreateFlags ^= THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
        }
    }

    auto preventThreadCreation = exchange_data.lookup_key("PreventThreadCreation");
    if (preventThreadCreation)
    {
        if (ProcessHandle == NtCurrentProcess
            && reinterpret_cast<int>(StartRoutine) != 0x0043f4f4
            && reinterpret_cast<int>(StartRoutine) != 0x004447d7)
        {
            return STATUS_INSUFFICIENT_RESOURCES;//STATUS_INVALID_PARAMETER STATUS_INVALID_HANDLE STATUS_INSUFFICIENT_RESOURCES
        }
    }

    auto dNtCreateThreadEx =
        exchange_data.lookup_trampoline<decltype(&HookedNtCreateThreadEx)>("NtCreateThreadEx");
    return dNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize,AttributeList);
}

DLLExport_C NTSTATUS NTAPI HookedNtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount)
{
    // TODO
    DWORD dwProcessId = GetProcessIdByThreadHandle(ThreadHandle);
    if (dwProcessId != HandleToULong(NtCurrentTeb()->ClientId.UniqueProcess)) //malware starts the thread of another process
    {
        DumpMalware(dwProcessId);
        TerminateProcessByProcessId(dwProcessId); //terminate it
        DbgPrint((PCH)"Malware called ResumeThread");
        DbgBreakPoint();
        return STATUS_SUCCESS;
    }
    else
    {
        auto dNtResumeThread =
            exchange_data.lookup_trampoline<decltype(&NtResumeThread)>(&NtResumeThread);
        return dNtResumeThread(ThreadHandle, PreviousSuspendCount);
    }
}

DLLExport_C NTSTATUS NTAPI HookedNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferSize, PULONG NumberofBytesWritten)
{
    auto& client = logClient();
    auto val = exchange_data.lookup_key("key");
    auto v2 = exchange_data.lookup_trampoline("LoadLibraryA");
    client.sendfmt("NtWriteVirtualMemory(ProcessHandle = %d, BaseAddress = 0x%08x, \n"
                    "                     Buffer = ..., BufferSize = 0x%04x, PNumberOfBytesWritten = 0x%08x)",
        ProcessHandle, BaseAddress,
        BufferSize, NumberofBytesWritten);

    auto dNtWriteVirtualMemory = exchange_data.lookup_trampoline<decltype(&NtWriteVirtualMemory)>(&NtWriteVirtualMemory);
    return dNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberofBytesWritten);
}

DLLExport_C NTSTATUS NTAPI HookedNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded)
{
    auto& client = logClient();
    client.sendfmt("NtReadVirtualMemory(ProcessHandle = %d, BaseAddress = 0x%08x, \n"
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
    client.sendfmt("NtOpenProcess(PProcessHandle = 0x%08x, 0xDesiredAccess = %08x, \n"
                    "              ObjectAttributes = 0x%04x, ClientId = 0x%08x) => %d",
        ProcessHandle, DesiredAccess, ObjectAttributes, ClientId, *ProcessHandle);

    return ans;
}
