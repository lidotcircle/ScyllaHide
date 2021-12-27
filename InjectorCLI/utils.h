#ifndef _INJECTOR_CLI_UTILS_H_
#define _INJECTOR_CLI_UTILS_H_

#include <string>
#include <Windows.h>

int GetPidByProcessName(const std::string& processName);

bool SetDebugPrivileges();
bool EnablePrivilege(LPCTSTR lpszPrivilegeName, BOOL bEnable);

std::string GetFilenameFromFileHandle(HANDLE hFile);

std::string GetLastErrorAsString();

#endif // _INJECTOR_CLI_UTILS_H_