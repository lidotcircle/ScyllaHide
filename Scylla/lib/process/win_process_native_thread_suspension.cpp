#include "process/win_process_native.h"
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <ntdll/ntdll.h>
#include <memory>
#include <stdexcept>
using namespace std;
using suspend_t = typename WinProcessNative::suspend_t;

SuspendHandle::~SuspendHandle() {}

struct ThreadSuspendInfo {
    HANDLE m_thread_handle;
    NTSTATUS m_suspend_status;
};

class ProcessInfo {
private:
    bool m_valid;
    HANDLE m_handle;
    HANDLE  m_pid;

public:
    vector<ThreadSuspendInfo> m_threads_info;

    ProcessInfo(): m_valid(false) {}
    ProcessInfo(HANDLE hProcess);

    bool   valid() const { return m_valid; }
    size_t numOfThreads() const { return this->m_threads_info.size(); }
    HANDLE PID() const { return m_pid; }
};

struct WinSuspendHandle: public SuspendHandle {
    HANDLE m_handle;
    ProcessInfo m_process_info;

    WinSuspendHandle() {}
    ~WinSuspendHandle() override {}
};

ProcessInfo::ProcessInfo(HANDLE hProcess): m_valid(false)
{
    PROCESS_BASIC_INFORMATION basicInfo = { 0 };
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &basicInfo, sizeof(basicInfo), nullptr);
    if (!NT_SUCCESS(status))
        return;

    ULONG size;
    status = NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
        return;

    std::shared_ptr<char> buffer = std::shared_ptr<char>(new char[size * 2], std::default_delete<char[]>());
    const PSYSTEM_PROCESS_INFORMATION systemProcessInfo = (PSYSTEM_PROCESS_INFORMATION)buffer.get();
    status = NtQuerySystemInformation(SystemProcessInformation, systemProcessInfo, 2 * size, nullptr);
    if (!NT_SUCCESS(status))
        return;

    // Count threads
    ULONG numThreads = 0;
    PSYSTEM_PROCESS_INFORMATION entry = systemProcessInfo;

    while (true) {
        if (entry->UniqueProcessId == basicInfo.UniqueProcessId)
        {
            numThreads = entry->NumberOfThreads;
            break;
        }
        if (entry->NextEntryOffset == 0)
            break;
        entry = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)entry + entry->NextEntryOffset);
    }

    if (numThreads == 0)
        return;

    // Fill process info
    this->m_pid = basicInfo.UniqueProcessId;
    this->m_handle = hProcess;

    // Fill thread IDs
    for (ULONG i = 0; i < numThreads; ++i) {
        ThreadSuspendInfo info;
        info.m_thread_handle = entry->Threads[i].ClientId.UniqueThread;
        this->m_threads_info.push_back(info);
    }

    this->m_valid = true;
}

suspend_t WinProcessNative::suspendThread()
{
    auto hProcess = this->rawhandle();

    ProcessInfo _processInfo(hProcess);
    if (!_processInfo.valid())
        return nullptr;

    auto retval = std::make_unique<WinSuspendHandle>();
    retval->m_process_info = std::move(_processInfo);
    auto& processInfo = retval->m_process_info;

    for (ULONG i = 0; i < processInfo.numOfThreads(); ++i)
    {
        auto& threadSuspendInfo = processInfo.m_threads_info[i];
        OBJECT_ATTRIBUTES objectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES((PUNICODE_STRING)nullptr, 0);
        CLIENT_ID clientId = { processInfo.PID(), threadSuspendInfo.m_thread_handle };

        // Open the thread by thread ID
        NTSTATUS status = NtOpenThread(&threadSuspendInfo.m_thread_handle, THREAD_SUSPEND_RESUME, &objectAttributes, &clientId);
        if (!NT_SUCCESS(status))
            return nullptr;

        // Suspend the thread, ignoring (but saving) STATUS_SUSPEND_COUNT_EXCEEDED errors
        status = NtSuspendThread(threadSuspendInfo.m_thread_handle, nullptr);
        threadSuspendInfo.m_suspend_status = status;
        if (!NT_SUCCESS(status) && status != STATUS_SUSPEND_COUNT_EXCEEDED)
            return nullptr;
    }

    return retval;
}

bool WinProcessNative::resumeThread(suspend_t handle) {
    if (!handle)
        throw std::invalid_argument("handle");
    auto WinSuspendHandlePtr = dynamic_cast<WinSuspendHandle*>(handle.get());
    if (!WinSuspendHandlePtr)
        throw std::invalid_argument("handle");

    auto& processInfo = WinSuspendHandlePtr->m_process_info;
    bool success = true;

    for (ULONG i = 0; i < processInfo.numOfThreads(); ++i)
    {
        auto& threadSuspendInfo = processInfo.m_threads_info[i];
        if (NT_SUCCESS(threadSuspendInfo.m_suspend_status) &&
            !NT_SUCCESS(NtResumeThread(threadSuspendInfo.m_thread_handle, nullptr)))
            success = false;
        if (!NT_SUCCESS(NtClose(threadSuspendInfo.m_thread_handle)))
            success = false;
    }

    return success;
}
