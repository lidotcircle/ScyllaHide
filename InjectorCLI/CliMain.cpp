#include <Windows.h>
#include <Shlwapi.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <cstdio>
#include <cstring>
#include <Scylla/Logger.h>
#include <Scylla/PebHider.h>
#include <Scylla/Settings.h>
#include <Scylla/Util.h>

#include "LogServer.h"
#include "DynamicMapping.h"
#include "..\HookLibrary\HookMain.h"
#include "ApplyHooking.h"
#include "../PluginGeneric/Injector.h"


scl::Settings g_settings;
scl::Logger g_log;
std::wstring g_scyllaHideIniPath;

HOOK_DLL_DATA g_hdd;


void ChangeBadWindowText();
void ReadSettings();
DWORD GetProcessIdByName(const char * processName);
bool startInjection(DWORD targetPid, const char * dllPath);
bool SetDebugPrivileges();
BYTE * ReadFileToMemory(const char * targetFilePath);
bool startInjectionProcess(HANDLE hProcess, BYTE * dllMemory);
bool StartHooking(HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase);
bool convertNumber(const wchar_t* str, unsigned long & result, int radix);

// Check if argument starts with text (case insensitive).
bool ArgStartsWith(const char* arg, const char* with);

// Check if argument starts with text (case insensitive) and return param after the text.
bool ArgStartsWith(const char* arg, const char* text, const char* &param);

#define PREFIX_PATH "C:\\Users\\Admin\\Documents\\Visual Studio 2010\\Projects\\ScyllaHide"

static void LogCallback(const wchar_t *msg)
{
    _putws(msg);
}

bool EnablePrivilege(LPCTSTR lpszPrivilegeName, BOOL bEnable)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES    tp;
    LUID luid;
    bool ret;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_READ, &hToken))
        return FALSE;

    if (!LookupPrivilegeValue(NULL, lpszPrivilegeName, &luid))
        return FALSE;

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;

    ret = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);

    return ret;
}

char* GetNameFromHandle(HANDLE hFile)
{
    BOOL bSuccess = FALSE;
    char pszFilename[MAX_PATH + 1];
    HANDLE hFileMap;

    DWORD dwFileSizeHi = 0;
    DWORD dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi);

    bool success = false;
    if (dwFileSizeLo == 0 && dwFileSizeHi == 0)
    {
        return nullptr;
    }

    hFileMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 1, NULL);

    if (hFileMap)
    {
        void* pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);

        if (pMem)
        {
            success = GetMappedFileName(GetCurrentProcess(), pMem, pszFilename, MAX_PATH); 
            UnmapViewOfFile(pMem);
        }

        CloseHandle(hFileMap);
    }

    if (!success) {
        return nullptr;
    }

    auto ans = new char[MAX_PATH + 1];
    strcpy(ans, pszFilename);
    return ans;
}

static char* requireDll[] = {
    "ntdll.dll",
    "kernel32.dll",
    "user32.dll",
};

int main(int argc, char* argv[])
{
    DWORD targetPid = 0;
    char * dllPath = 0;
    LogServer srv(0);
    srv.init();
    udpPort = srv.GetPort();
    udpAddr = srv.GetAddr();

    auto wstrPath = scl::GetModuleFileNameW();
    wstrPath.resize(wstrPath.find_last_of('\\') + 1);

    g_scyllaHideIniPath = wstrPath + scl::Settings::kFileName;

    auto log_file = wstrPath + scl::Logger::kFileName;
    g_log.SetLogFile(log_file.c_str());
    g_log.SetLogCb(scl::Logger::Info, LogCallback);
    g_log.SetLogCb(scl::Logger::Error, LogCallback);

    ReadNtApiInformation(&g_hdd);
    SetDebugPrivileges();
    //ChangeBadWindowText();
    g_settings.Load(g_scyllaHideIniPath.c_str());
    ReadSettings();

    bool waitOnExit = true;

    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFO si = { 0 };
    DEBUG_EVENT de;
    bool newProcess = false;
    si.cb = sizeof(si);

    if (argc >= 3)
    {
        char* pid;
        char* exe_path;

        if (ArgStartsWith(argv[1], "pid:", pid))
        {
            auto radix = 10;
            if (csstr(pid, "0x") == pid)
                radix = 16, pid += 2;
            if (!convertNumber(pid, targetPid, radix))
                targetPid = 0;
        }
        else if (ArgStartsWith(argv[1], "new:", exe_path))
        {
            if (!EnablePrivilege(SE_DEBUG_NAME, TRUE)) {
                fprintf(stderr, "adjust debug privilege failed; error code = 0x%08X\n", GetLastError());
                return 1;
            }
            if (!CreateProcess(NULL, exe_path, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS | DEBUG_PROCESS, NULL, NULL, &si, &pi)) {
                fprintf(stderr, "CreateProcess(\"%s\") failed; error code = 0x%08X\n", exe_path, GetLastError());
                return 1;
            }

            auto ndll = sizeof(requireDll) / sizeof(requireDll[0]);
            auto dllv = new bool[ndll];
            for (size_t i = 0; i < ndll; i++) dllv[i] = false;

            while (true) {
                if (!WaitForDebugEvent(&de, INFINITE)) {
                    fprintf(stderr, "Debug process failed; error code = 0x%08X\n", GetLastError());
                    delete dllv;
                    return 1;
                }

                if (de.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
                    auto filename = GetNameFromHandle(de.u.LoadDll.hFile);

                    if (!filename) {
                        fprintf(stderr, "can't get loaded library\n");
                        delete dllv;
                        return 1;
                    }
                    printf("%s: load %s\n", exe_path, filename);

                    for (size_t i = 0; i < ndll; i++) {
                        if (strcmp(requireDll[i], filename) == 0) {
                            dllv[i] = true;
                        }
                    }
                    delete filename;

                    bool readygo = true;
                    for (size_t i = 0; i < ndll; i++)
                        readygo = readygo && dllv[i];

                    if (readygo) {
                        delete dllv;
                        break;
                    }
                }
                else if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
                    fprintf(stderr, "NOEXPECTED: debuggee exit\n");
                    delete dllv;
                    return 1;
                }

                ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
            }

            targetPid = pi.dwProcessId;
            newProcess = true;
        }
        else
            targetPid = GetProcessIdByName(argv[1]);

        dllPath = argv[2];

        if (argc >= 4)
            waitOnExit = !(ArgStartsWith(argv[3], "nowait"));
    }
    else
    {

#ifdef _WIN64
        targetPid = GetProcessIdByName("scylla_x64.exe");//scylla_x64
        dllPath = PREFIX_PATH "\\Release\\HookLibraryx64.dll";
#else
        targetPid = GetProcessIdByName("ThemidaTest.exe");//GetProcessIdByName("ThemidaTest.exe");//GetProcessIdByName("VMProtect.vmp.exe");//GetProcessIdByName("scylla_x86.exe");
        dllPath = PREFIX_PATH "\\Release\\HookLibraryx86.dll";
#endif
    }

    int result = 0;

    if (targetPid && dllPath)
    {
        printf("\nPID\t: %d 0x%X\nDLL Path: %s\n\n", targetPid, targetPid, dllPath);
        if (!startInjection(targetPid, dllPath))
            result = 1; // failure
    }
    else
    {
        printf("Usage: %s <process name>   <dll path> [nowait]\n", argv[0]);
        printf("Usage: %s pid:<process id> <dll path> [nowait]\n", argv[0]);
        printf("Usage: %s new:<executable> <dll path>",            argv[0]);
    }

    if (newProcess) {
        if(!DebugActiveProcessStop(pi.dwProcessId)){
            fprintf(stderr, "detach failed; error code = 0x%08X\n", GetLastError());
            result = 1;
        }
        else {
            printf("resume process\n");
        }
    }

    if (newProcess) {
        srv.poll();
    }

    if (waitOnExit && !newProcess)
        getchar();

    return 0;
}

static bool StartHooking(HANDLE hProcess, BYTE * dllMemory, DWORD_PTR imageBase)
{
    g_hdd.dwProtectedProcessId = 0;
    g_hdd.EnableProtectProcessId = FALSE;

    DWORD peb_flags = 0;
    if (g_settings.opts().fixPebBeingDebugged)
        peb_flags |= PEB_PATCH_BeingDebugged;
    if (g_settings.opts().fixPebHeapFlags)
        peb_flags |= PEB_PATCH_HeapFlags;
    if (g_settings.opts().fixPebNtGlobalFlag)
        peb_flags |= PEB_PATCH_NtGlobalFlag;
    if (g_settings.opts().fixPebStartupInfo)
        peb_flags |= PEB_PATCH_ProcessParameters;
    if (g_settings.opts().fixPebOsBuildNumber)
        peb_flags |= PEB_PATCH_OsBuildNumber;

    ApplyPEBPatch(hProcess, peb_flags);
    if (g_settings.opts().fixPebOsBuildNumber)
        ApplyNtdllVersionPatch(hProcess);

    if (dllMemory == nullptr || imageBase == 0)
        return peb_flags != 0; // Not injecting hook DLL

    return ApplyHook(&g_hdd, hProcess, dllMemory, imageBase);
}

bool startInjectionProcess(HANDLE hProcess, BYTE * dllMemory)
{
    PROCESS_SUSPEND_INFO suspendInfo;
    if (!SafeSuspendProcess(hProcess, &suspendInfo))
        return false;

    if (g_settings.opts().removeDebugPrivileges)
    {
        RemoveDebugPrivileges(hProcess);
    }

    const bool injectDll = g_settings.hook_dll_needed();
    bool success = false;
    if (injectDll)
    {
        LPVOID remoteImageBase = MapModuleToProcess(hProcess, dllMemory, true);
        if (remoteImageBase != nullptr)
        {
            FillHookDllData(hProcess, &g_hdd);
            DWORD hookDllDataAddressRva = GetDllFunctionAddressRVA(dllMemory, "HookDllData");

            if (StartHooking(hProcess, dllMemory, (DWORD_PTR)remoteImageBase))
            {
                if (WriteProcessMemory(hProcess, (LPVOID)((DWORD_PTR)hookDllDataAddressRva + (DWORD_PTR)remoteImageBase), &g_hdd, sizeof(HOOK_DLL_DATA), 0))
                {
                    printf("Hook injection successful, image base %p\n", remoteImageBase);
                    success = true;
                }
                else
                {
                    printf("Failed to write hook dll data\n");
                }
            }
        }
    }
    else
    {
        if (StartHooking(hProcess, nullptr, 0))
            printf("PEB patch successful, hook injection not needed\n");
        success = true;
    }

    SafeResumeProcess(&suspendInfo);

    return success;
}

bool startInjection(DWORD targetPid, const char * dllPath)
{
    bool result = false;

    HANDLE hProcess = OpenProcess( PROCESS_SUSPEND_RESUME | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION,
        0, targetPid);
    if (hProcess)
    {
        BYTE * dllMemory = ReadFileToMemory(dllPath);
        if (dllMemory)
        {
            result = startInjectionProcess(hProcess, dllMemory);
            if (g_settings.opts().killAntiAttach)
            {
                if (!ApplyAntiAntiAttach(targetPid))
                {
                    printf("Anti-Anti-Attach failed\n");
                }
            }
            free(dllMemory);
        }
        else
        {
            printf("Cannot read file to memory %s\n", dllPath);
        }
        CloseHandle(hProcess);
    }
    else
    {
        printf("Cannot open process handle %d\n", targetPid);
    }

    return result;
}

bool SetDebugPrivileges()
{
    TOKEN_PRIVILEGES Debug_Privileges;
	bool retVal = false;

    if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Debug_Privileges.Privileges[0].Luid))
	{
		HANDLE hToken = 0;
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
		{
			Debug_Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			Debug_Privileges.PrivilegeCount = 1;

			retVal = AdjustTokenPrivileges(hToken, FALSE, &Debug_Privileges, 0, NULL, NULL) != FALSE;

			CloseHandle(hToken);
		}
	}

    return retVal;
}

DWORD GetProcessIdByName(const CHAR * processName)
{
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        printf("Error getting first process\n");
        CloseHandle(hProcessSnap);
        return 0;
    }

    DWORD pid = 0;

    do
    {
        if (!strcmp(pe32.szExeFile, processName))
        {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return pid;
}

void ReadSettings()
{
    g_hdd.EnableGetLocalTimeHook = g_settings.opts().hookGetLocalTime;
    g_hdd.EnableGetSystemTimeHook = g_settings.opts().hookGetSystemTime;
    g_hdd.EnableGetTickCount64Hook = g_settings.opts().hookGetTickCount64;
    g_hdd.EnableGetTickCountHook = g_settings.opts().hookGetTickCount;
    g_hdd.EnableKiUserExceptionDispatcherHook = g_settings.opts().hookKiUserExceptionDispatcher;
    g_hdd.EnableNtCloseHook = g_settings.opts().hookNtClose;
    g_hdd.EnableNtContinueHook = g_settings.opts().hookNtContinue;
    g_hdd.EnableNtCreateThreadExHook = g_settings.opts().hookNtCreateThreadEx;
    g_hdd.EnableNtGetContextThreadHook = g_settings.opts().hookNtGetContextThread;
    g_hdd.EnableNtQueryInformationProcessHook = g_settings.opts().hookNtQueryInformationProcess;
    g_hdd.EnableNtQueryObjectHook = g_settings.opts().hookNtQueryObject;
    g_hdd.EnableNtQueryPerformanceCounterHook = g_settings.opts().hookNtQueryPerformanceCounter;
    g_hdd.EnableNtQuerySystemInformationHook = g_settings.opts().hookNtQuerySystemInformation;
    g_hdd.EnableNtQuerySystemTimeHook = g_settings.opts().hookNtQuerySystemTime;
    g_hdd.EnableNtSetContextThreadHook = g_settings.opts().hookNtSetContextThread;
    g_hdd.EnableNtSetDebugFilterStateHook = g_settings.opts().hookNtSetDebugFilterState;
    g_hdd.EnableNtSetInformationThreadHook = g_settings.opts().hookNtSetInformationThread;
    g_hdd.EnableNtUserBlockInputHook = g_settings.opts().hookNtUserBlockInput;
    g_hdd.EnableNtUserBuildHwndListHook = g_settings.opts().hookNtUserBuildHwndList;
    g_hdd.EnableNtUserFindWindowExHook = g_settings.opts().hookNtUserFindWindowEx;
    g_hdd.EnableNtUserQueryWindowHook = g_settings.opts().hookNtUserQueryWindow;
    g_hdd.EnableNtUserGetForegroundWindowHook = g_settings.opts().hookNtUserGetForegroundWindow;
    g_hdd.EnableNtYieldExecutionHook = g_settings.opts().hookNtYieldExecution;
    g_hdd.EnableOutputDebugStringHook = g_settings.opts().hookOutputDebugStringA;
    g_hdd.EnablePebBeingDebugged = g_settings.opts().fixPebBeingDebugged;
    g_hdd.EnablePebHeapFlags = g_settings.opts().fixPebHeapFlags;
    g_hdd.EnablePebNtGlobalFlag = g_settings.opts().fixPebNtGlobalFlag;
    g_hdd.EnablePebStartupInfo = g_settings.opts().fixPebStartupInfo;
    g_hdd.EnablePebOsBuildNumber = g_settings.opts().fixPebOsBuildNumber;
    g_hdd.EnablePreventThreadCreation = g_settings.opts().preventThreadCreation;
    g_hdd.EnableProtectProcessId = g_settings.opts().protectProcessId;
}

bool convertNumber(const char* str, unsigned long & result, int radix)
{
    errno = 0;
    char* end;
    result = strtol(str, &end, radix);
    if(!result && end == str)
        return false;
    if(result == ULLONG_MAX && errno)
        return false;
    if(*end)
        return false;
    return true;
}

bool ArgStartsWith(const char* arg, const char* with)
{
    return StrCmpNA(arg, with, strlen(with)) == 0;
}

bool ArgStartsWith(const char* arg, const char* text, const char* &param)
{
    auto len = strlen(text);

    if (StrCmpNA(arg, text, len) == 0 && arg[len])
    {
        param = arg + len;
        return true;
    }

    param = nullptr;
    return false;
}
