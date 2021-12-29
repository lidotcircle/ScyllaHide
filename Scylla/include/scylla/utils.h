#ifndef _SCYLLA_UTILS_H_
#define _SCYLLA_UTILS_H_

#include <string>
#include <memory>
#include <Windows.h>
#include "process/win_process_native.h"

int GetPidByProcessName(const std::string& processName);
const char* GetProcessNameByPid(int pid);

enum SuspendingState {
    SUSPEND_ON_NTDLL_KERNEL32_LOADED,
    SUSPEND_ON_ALL_MODULE_LOADED,
    SUSPEND_ON_SYSTEM_BREAKPOINT,
    SUSPEND_ON_ENTRYPOINT,
};
WinProcessNative::suspend_t CreateProcessAndSuspend(
    const std::string& cmdline, std::shared_ptr<WinProcessNative>& process, SuspendingState state);

bool SetDebugPrivileges();
bool EnablePrivilege(LPCTSTR lpszPrivilegeName, BOOL bEnable);

std::string GetFilenameFromFileHandle(HANDLE hFile);

std::string GetLastErrorAsString();

const char* ChooserFile(const char* filter);
const char* SaveFileTo(const char* filter, const std::string& default);

#endif // _SCYLLA_UTILS_H_