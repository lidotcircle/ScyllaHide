#include <Windows.h>
#include <ntdll/ntdll.h>
#include "exchange_data.h"
#include "HookHelper.h"


#define BACKUP_RETURNLENGTH() \
    ULONG TempReturnLength = 0; \
    if(ReturnLength != nullptr) \
        TempReturnLength = *ReturnLength

#define RESTORE_RETURNLENGTH() \
    if(ReturnLength != nullptr) \
        (*ReturnLength) = TempReturnLength


NTSTATUS NTAPI HookedNtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength)
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

NTSTATUS NTAPI HookedNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
    auto dNtQuerySystemInformation = exchange_data.lookup_trampoline<decltype(&NtQuerySystemInformation)>(&NtQuerySystemInformation);

    switch (SystemInformationClass)
    {
        case SystemKernelDebuggerInformation: {
            BACKUP_RETURNLENGTH();
            ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation)->KernelDebuggerEnabled = FALSE;
            ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation)->KernelDebuggerNotPresent = TRUE;
            RESTORE_RETURNLENGTH();
        } break;
    };
    if (SystemInformationClass == SystemKernelDebuggerInformation ||
        SystemInformationClass == SystemProcessInformation ||
        SystemInformationClass == SystemSessionProcessInformation ||
        SystemInformationClass == SystemHandleInformation ||
        SystemInformationClass == SystemExtendedHandleInformation ||
        SystemInformationClass == SystemExtendedProcessInformation ||   // Vista+
        SystemInformationClass == SystemCodeIntegrityInformation ||     // Vista+
        SystemInformationClass == SystemKernelDebuggerInformationEx ||  // 8.1+
        SystemInformationClass == SystemKernelDebuggerFlags ||          // 10+
        SystemInformationClass == SystemCodeIntegrityUnlockInformation) // 10+
    {
        NTSTATUS ntStat = dNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
        if (NT_SUCCESS(ntStat) && SystemInformation != nullptr && SystemInformationLength != 0)
        {
            if (SystemInformationClass == SystemKernelDebuggerInformation)
            {

            }
            else if (SystemInformationClass == SystemHandleInformation)
            {
                BACKUP_RETURNLENGTH();
                ULONG ReturnLengthAdjust = 0;

                FilterHandleInfo((PSYSTEM_HANDLE_INFORMATION)SystemInformation, &ReturnLengthAdjust);

                if (ReturnLengthAdjust <= TempReturnLength)
                    TempReturnLength -= ReturnLengthAdjust;
                RESTORE_RETURNLENGTH();
            }
            else if (SystemInformationClass == SystemExtendedHandleInformation)
            {
                BACKUP_RETURNLENGTH();
                ULONG ReturnLengthAdjust = 0;

                FilterHandleInfoEx((PSYSTEM_HANDLE_INFORMATION_EX)SystemInformation, &ReturnLengthAdjust);

                if (ReturnLengthAdjust <= TempReturnLength)
                    TempReturnLength -= ReturnLengthAdjust;
                RESTORE_RETURNLENGTH();
            }
            else if (SystemInformationClass == SystemProcessInformation ||
                    SystemInformationClass == SystemSessionProcessInformation ||
                    SystemInformationClass == SystemExtendedProcessInformation)
            {
                BACKUP_RETURNLENGTH();

                PSYSTEM_PROCESS_INFORMATION ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
                if (SystemInformationClass == SystemSessionProcessInformation)
                    ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((PSYSTEM_SESSION_PROCESS_INFORMATION)SystemInformation)->Buffer;

                FilterProcess(ProcessInfo);
                FakeCurrentParentProcessId(ProcessInfo);
                FakeCurrentOtherOperationCount(ProcessInfo);

                RESTORE_RETURNLENGTH();
            }
            else if (SystemInformationClass == SystemCodeIntegrityInformation)
            {
                BACKUP_RETURNLENGTH();

                ((PSYSTEM_CODEINTEGRITY_INFORMATION)SystemInformation)->CodeIntegrityOptions = CODEINTEGRITY_OPTION_ENABLED;

                RESTORE_RETURNLENGTH();
            }
            else if (SystemInformationClass == SystemKernelDebuggerInformationEx)
            {
                BACKUP_RETURNLENGTH();

                ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation)->DebuggerAllowed = FALSE;
                ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation)->DebuggerEnabled = FALSE;
                ((PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation)->DebuggerPresent = FALSE;

                RESTORE_RETURNLENGTH();
            }
            else if (SystemInformationClass == SystemKernelDebuggerFlags)
            {
                BACKUP_RETURNLENGTH();

                *(PUCHAR)SystemInformation = 0;

                RESTORE_RETURNLENGTH();
            }
            else if (SystemInformationClass == SystemCodeIntegrityUnlockInformation)
            {
                BACKUP_RETURNLENGTH();

                // The size of the buffer for this class changed from 4 to 36, but the output should still be all zeroes
                RtlZeroMemory(SystemInformation, SystemInformationLength);

                RESTORE_RETURNLENGTH();
            }
        }

        return ntStat;
    }
    return dNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}

NTSTATUS NTAPI HookedNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
{
    if (NumManualSyscalls == 0 &&
        InterlockedOr(&InstrumentationCallbackHookInstalled, 0x1) == 0)
    {
        InstallInstrumentationCallbackHook(NtCurrentProcess, FALSE);
    }

    NTSTATUS Status;
    if (ProcessInformationClass == ProcessDebugObjectHandle && // Handle ProcessDebugObjectHandle early
        ProcessInformation != nullptr &&
        ProcessInformationLength == sizeof(HANDLE) &&
        (ProcessHandle == NtCurrentProcess || HandleToULong(NtCurrentTeb()->ClientId.UniqueProcess) == GetProcessIdByProcessHandle(ProcessHandle)))
    {
        // Verify (1) that the handle has PROCESS_QUERY_INFORMATION access, and (2) that writing
        // to ProcessInformation and/or ReturnLength does not cause any access or alignment violations
        Status = HookDllData.dNtQueryInformationProcess(ProcessHandle,
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
        Status = HookDllData.dNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);

        if (NT_SUCCESS(Status) && ProcessInformation != nullptr && ProcessInformationLength != 0)
        {
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
        }

        return Status;
    }
    return HookDllData.dNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}

NTSTATUS NTAPI HookedNtSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength)
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
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
    return HookDllData.dNtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
}

NTSTATUS NTAPI HookedNtQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength)
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    NTSTATUS ntStat = HookDllData.dNtQueryObject(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);

    if ((ObjectInformationClass == ObjectTypesInformation ||
        ObjectInformationClass == ObjectTypeInformation) &&
        (NT_SUCCESS(ntStat) && ObjectInformation))
    {
        if (ObjectInformationClass == ObjectTypesInformation)
        {
            BACKUP_RETURNLENGTH();

            FilterObjects((POBJECT_TYPES_INFORMATION)ObjectInformation);

            RESTORE_RETURNLENGTH();
        }
        else if (ObjectInformationClass == ObjectTypeInformation)
        {
            BACKUP_RETURNLENGTH();

            FilterObject((POBJECT_TYPE_INFORMATION)ObjectInformation, false);

            RESTORE_RETURNLENGTH();
        }
    }

    return ntStat;
}

NTSTATUS NTAPI HookedNtYieldExecution()
{
    HookDllData.dNtYieldExecution();
    return STATUS_ACCESS_DENIED; //better than STATUS_SUCCESS or STATUS_NO_YIELD_PERFORMED
}

NTSTATUS NTAPI HookedNtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
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

    NTSTATUS ntStat = HookDllData.dNtGetContextThread(ThreadHandle, ThreadContext);

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

NTSTATUS NTAPI HookedNtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
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

    NTSTATUS ntStat = HookDllData.dNtSetContextThread(ThreadHandle, ThreadContext);

    if (ContextBackup)
    {
        ThreadContext->ContextFlags = ContextBackup;
    }

    return ntStat;
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
void NTAPI HookedKiUserExceptionDispatcher()
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
VOID NAKED NTAPI HookedKiUserExceptionDispatcher()// (PEXCEPTION_RECORD pExcptRec, PCONTEXT ContextFrame) //remove DRx Registers
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
        jmp HookDllData.dKiUserExceptionDispatcher
    }

    //return HookDllData.dKiUserExceptionDispatcher(pExcptRec, ContextFrame);
}
#endif

NTSTATUS NTAPI HookedNtContinue(PCONTEXT ThreadContext, BOOLEAN RaiseAlert) //restore DRx Registers
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
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

    return HookDllData.dNtContinue(ThreadContext, RaiseAlert);
}

NTSTATUS NTAPI HookedNtClose(HANDLE Handle)
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    OBJECT_HANDLE_FLAG_INFORMATION flags;
    NTSTATUS Status;
    if (HookDllData.dNtQueryObject != nullptr)
        Status = HookDllData.dNtQueryObject(Handle, ObjectHandleFlagInformation, &flags, sizeof(OBJECT_HANDLE_FLAG_INFORMATION), nullptr);
    else
        Status = NtQueryObject(Handle, ObjectHandleFlagInformation, &flags, sizeof(OBJECT_HANDLE_FLAG_INFORMATION), nullptr);

    if (NT_SUCCESS(Status))
    {
        if (flags.ProtectFromClose)
        {
            return STATUS_HANDLE_NOT_CLOSABLE;
        }

        return HookDllData.dNtClose(Handle);
    }

    return STATUS_INVALID_HANDLE;
}

NTSTATUS NTAPI HookedNtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options)
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    if (Options & DUPLICATE_CLOSE_SOURCE)
    {
        // If a process is being debugged and duplicates a handle with DUPLICATE_CLOSE_SOURCE, *and* the handle has the ProtectFromClose bit set, a STATUS_HANDLE_NOT_CLOSABLE exception will occur.
        // This is actually the exact same exception we already check for in NtClose, but the difference is that this NtClose call happens inside the kernel which we obviously can't hook.
        // When a process is not being debugged, NtDuplicateObject will simply return success without closing the source. This is because ObDuplicateObject ignores NtClose return values
        OBJECT_HANDLE_FLAG_INFORMATION HandleFlags;
        NTSTATUS Status;
        if (HookDllData.dNtQueryObject != nullptr)
            Status = HookDllData.dNtQueryObject(SourceHandle, ObjectHandleFlagInformation, &HandleFlags, sizeof(HandleFlags), nullptr);
        else
            Status = NtQueryObject(SourceHandle, ObjectHandleFlagInformation, &HandleFlags, sizeof(HandleFlags), nullptr);

        if (NT_SUCCESS(Status) && HandleFlags.ProtectFromClose)
        {
            // Prevent the exception
            Options &= ~DUPLICATE_CLOSE_SOURCE;
        }
    }

    return HookDllData.dNtDuplicateObject(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
}

NTSTATUS WINAPI HookedNtQuerySystemTime(PLARGE_INTEGER SystemTime)
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    if (!OneNativeSysTime.QuadPart)
    {
        HookDllData.dNtQuerySystemTime(&OneNativeSysTime);
    }
    else
    {
        OneNativeSysTime.QuadPart++;
    }

    NTSTATUS ntStat = HookDllData.dNtQuerySystemTime(SystemTime);

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

NTSTATUS NTAPI HookedNtQueryPerformanceCounter(PLARGE_INTEGER PerformanceCounter, PLARGE_INTEGER PerformanceFrequency)
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    if (!OnePerformanceCounter.QuadPart)
    {
        HookDllData.dNtQueryPerformanceCounter(&OnePerformanceCounter, &OnePerformanceFrequency);
    }
    else
    {
        OnePerformanceCounter.QuadPart++;
    }

    NTSTATUS ntStat = HookDllData.dNtQueryPerformanceCounter(PerformanceCounter, PerformanceFrequency);

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

BOOL NTAPI HookedNtUserBlockInput(BOOL fBlockIt)
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
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

HWND NTAPI HookedNtUserFindWindowEx(HWND hWndParent, HWND hWndChildAfter, PUNICODE_STRING lpszClass, PUNICODE_STRING lpszWindow, DWORD dwType)
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    HWND resultHwnd = HookDllData.dNtUserFindWindowEx(hWndParent, hWndChildAfter, lpszClass, lpszWindow, dwType);
    if (resultHwnd)
    {
        if (IsWindowClassNameBad(lpszClass) || IsWindowNameBad(lpszWindow))
        {
            return 0;
        }

        if (HookDllData.EnableProtectProcessId == TRUE)
        {
            DWORD dwProcessId;
            if (HookDllData.dNtUserQueryWindow)
            {
                dwProcessId = HandleToULong(HookDllData.dNtUserQueryWindow(resultHwnd, WindowProcess));
            }
            else
            {
                dwProcessId = HandleToULong(HookDllData.NtUserQueryWindow(resultHwnd, WindowProcess));
            }

            if (dwProcessId == HookDllData.dwProtectedProcessId)
            {
                return 0;
            }
        }
    }
    return resultHwnd;
}

NTSTATUS NTAPI HookedNtSetDebugFilterState(ULONG ComponentId, ULONG Level, BOOLEAN State)
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    return HasDebugPrivileges(NtCurrentProcess) ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
}

NTSTATUS NTAPI HookedNtUserBuildHwndList(HDESK hDesktop, HWND hwndParent, BOOLEAN bChildren, ULONG dwThreadId, ULONG lParam, HWND* pWnd, PULONG pBufSize)
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    NTSTATUS ntStat = HookDllData.dNtUserBuildHwndList(hDesktop, hwndParent, bChildren, dwThreadId, lParam, pWnd, pBufSize);

    if (NT_SUCCESS(ntStat) && pWnd != nullptr && pBufSize != nullptr)
    {
        FilterHwndList(pWnd, pBufSize);
    }

    return ntStat;
}

NTSTATUS NTAPI HookedNtUserBuildHwndList_Eight(HDESK hDesktop, HWND hwndParent, BOOLEAN bChildren, BOOLEAN bUnknownFlag, ULONG dwThreadId, ULONG lParam, HWND* pWnd, PULONG pBufSize)
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    NTSTATUS ntStat = ((t_NtUserBuildHwndList_Eight)HookDllData.dNtUserBuildHwndList)(hDesktop, hwndParent, bChildren, bUnknownFlag, dwThreadId, lParam, pWnd, pBufSize);

    if (NT_SUCCESS(ntStat) && pWnd != nullptr && pBufSize != nullptr)
    {
        FilterHwndList(pWnd, pBufSize);
    }

    return ntStat;
}

HANDLE NTAPI HookedNtUserQueryWindow(HWND hwnd, WINDOWINFOCLASS WindowInfo)
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    if ((WindowInfo == WindowProcess || WindowInfo == WindowThread) && IsWindowBad(hwnd))
    {
        if (WindowInfo == WindowProcess)
            return NtCurrentTeb()->ClientId.UniqueProcess;
        if (WindowInfo == WindowThread)
            return NtCurrentTeb()->ClientId.UniqueThread;
    }
    return HookDllData.dNtUserQueryWindow(hwnd, WindowInfo);
}

HWND NTAPI HookedNtUserGetForegroundWindow()
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    HWND Hwnd = HookDllData.dNtUserGetForegroundWindow();
    if (Hwnd != nullptr && IsWindowBad(Hwnd))
    {
        Hwnd = (HWND)HookDllData.NtUserGetThreadState(THREADSTATE_ACTIVEWINDOW);
    }
    return Hwnd;
}

//WIN XP: CreateThread -> CreateRemoteThread -> NtCreateThread
NTSTATUS NTAPI HookedNtCreateThread(PHANDLE ThreadHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,HANDLE ProcessHandle,PCLIENT_ID ClientId,PCONTEXT ThreadContext,PINITIAL_TEB InitialTeb,BOOLEAN CreateSuspended)
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    if (ProcessHandle == NtCurrentProcess)
    {
        return STATUS_INSUFFICIENT_RESOURCES;//STATUS_INVALID_PARAMETER STATUS_INVALID_HANDLE STATUS_INSUFFICIENT_RESOURCES
    }
    return HookDllData.dNtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId,ThreadContext, InitialTeb,CreateSuspended);
}

//WIN 7: CreateThread -> CreateRemoteThreadEx -> NtCreateThreadEx
NTSTATUS NTAPI HookedNtCreateThreadEx(PHANDLE ThreadHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,HANDLE ProcessHandle,PUSER_THREAD_START_ROUTINE StartRoutine,PVOID Argument,ULONG CreateFlags,ULONG_PTR ZeroBits,SIZE_T StackSize,SIZE_T MaximumStackSize,PPS_ATTRIBUTE_LIST AttributeList)
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    auto client = logClient();
    client->sendfmt("NtCreateThreadEx(PThreadHandle = 0x%04x, ACCESS_MASK = 0x%08x, POBJECT_ATTRIBUTES = 0x%08x, \n"
                    "                 ProcessHandle = 0x%04x, StartRoutine = 0x%08x, Argument = 0x%08x,\n"
                    "                 CreationFlags = 0x%08x, ZeroBits = %d, StackSize = %x, MaxStackSize = %x,\n"
                    "                 AttributeList = 0x%08x)",
        ThreadHandle, DesiredAccess, ObjectAttributes,
        ProcessHandle, StartRoutine, Argument,
        CreateFlags, ZeroBits, StackSize, MaximumStackSize,
        AttributeList);

    if (HookDllData.EnableNtCreateThreadExHook == TRUE) //prevent hide from debugger
    {
        if (CreateFlags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER)
        {
            CreateFlags ^= THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
        }
    }

    if (HookDllData.EnablePreventThreadCreation == TRUE)
    {
        if (ProcessHandle == NtCurrentProcess
            && reinterpret_cast<int>(StartRoutine) != 0x0043f4f4
            && reinterpret_cast<int>(StartRoutine) != 0x004447d7)
        {
            return STATUS_INSUFFICIENT_RESOURCES;//STATUS_INVALID_PARAMETER STATUS_INVALID_HANDLE STATUS_INSUFFICIENT_RESOURCES
        }
    }

    return HookDllData.dNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize,AttributeList);
}

NTSTATUS NTAPI HookedNtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount)
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
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
        return HookDllData.dNtResumeThread(ThreadHandle, PreviousSuspendCount);
    }
}

NTSTATUS NTAPI HookedNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferSize, PULONG NumberofBytesWritten)
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    auto client = logClient();
    auto val = exchange_data.lookup_key("key");
    auto v2 = exchange_data.lookup_trampoline("LoadLibraryA");
    client->sendfmt("NtWriteVirtualMemory(ProcessHandle = %d, BaseAddress = 0x%08x, \n"
                    "                     Buffer = ..., BufferSize = 0x%04x, PNumberOfBytesWritten = 0x%08x)%lx %lx %lx %s",
        ProcessHandle, BaseAddress,
        BufferSize, NumberofBytesWritten, val, v2, &exchange_data, val);

    return HookDllData.dNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberofBytesWritten);
}

NTSTATUS NTAPI HookedNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded)
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    auto client = logClient();
    client->sendfmt("NtReadVirtualMemory(ProcessHandle = %d, BaseAddress = 0x%08x, \n"
                    "                    Buffer = ..., NumberOfBytesToRead = 0x%08x, \n"
                    "                    PNumberOfBytesReaded = 0x%08x)",
        ProcessHandle, BaseAddress, NumberOfBytesToRead, NumberOfBytesReaded);

    return HookDllData.dNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
}

NTSTATUS NTAPI HookedNtOpenProcess(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
)
{
#pragma comment(linker, "/EXPORT:" __FUNCTION__ "=" __FUNCDNAME__)
    auto ans = HookDllData.dNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);

    auto client = logClient();
    client->sendfmt("NtOpenProcess(PProcessHandle = 0x%08x, 0xDesiredAccess = %08x, \n"
                    "              ObjectAttributes = 0x%04x, ClientId = 0x%08x) => %d",
        ProcessHandle, DesiredAccess, ObjectAttributes, ClientId, *ProcessHandle);

    return ans;
}
