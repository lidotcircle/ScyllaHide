#ifndef _SCYLLA_UTILS_H_
#define _SCYLLA_UTILS_H_

#include <string>
#include <memory>
#include <vector>
#include <Windows.h>
#include <TlHelp32.h>
#include "process/win_process_native.h"
#include "utils.hpp"

int GetPidByProcessName(const std::string& processName);
const char* GetProcessNameByPid(int pid);

enum SuspendingState {
    SUSPEND_ON_NO_SUSPEND,
    SUSPEND_ON_NTDLL_KERNEL32_LOADED,
    SUSPEND_ON_ALL_MODULE_LOADED,
    SUSPEND_ON_SYSTEM_BREAKPOINT,
    SUSPEND_ON_ENTRYPOINT,
};
std::shared_ptr<WinProcessNative>
CreateProcessAndSuspend(const std::string& exefile, const std::string& args, 
                        SuspendingState state, WinProcessNative::suspend_t& suspend);

bool SetDebugPrivileges();
bool EnablePrivilege(LPCTSTR lpszPrivilegeName, BOOL bEnable);

std::string GetFilenameFromFileHandle(HANDLE hFile);

const char* ChooserFile(const char* filter);
const char* SaveFileTo(const char* filter, const std::string& default);

std::vector<PROCESSENTRY32> GetProcessList();

#endif // _SCYLLA_UTILS_H_