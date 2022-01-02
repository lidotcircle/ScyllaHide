#include "process/memory_map_pefile.h"
#include "scylla/utils.h"
#include "utils.hpp"
#include <iostream>
#include <thread>
#include <set>
#include <string>
#include <TlHelp32.h>
#include <Psapi.h>
#include <Windows.h>
using namespace std;

const char* ChooserFile(const char* filter) 
{
    static char syFile[MAX_PATH];
    size_t convertedChars = 0;
    OPENFILENAME sfn;

    ZeroMemory( &sfn , sizeof( sfn));
    sfn.lStructSize = sizeof ( sfn );
    sfn.hwndOwner = NULL ;
    sfn.lpstrFile = syFile ;
    sfn.lpstrFile[0] = '\0';
    sfn.nMaxFile = sizeof( syFile );
    sfn.lpstrFilter = filter;
    sfn.nFilterIndex =1;
    sfn.lpstrFileTitle = NULL ;
    sfn.nMaxFileTitle = 0 ;
    sfn.lpstrInitialDir=NULL;

    sfn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOVALIDATE | OFN_HIDEREADONLY;
    if (GetOpenFileName( &sfn ) != TRUE)
        return nullptr;

    return syFile;
}

const char* SaveFileTo(const char* filter, const string& default)
{
    static char syFile[MAX_PATH];
    size_t convertedChars = 0;
    OPENFILENAME sfn;

    ZeroMemory( &sfn , sizeof( sfn));
    sfn.lStructSize = sizeof ( sfn );
    sfn.hwndOwner = NULL ;
    sfn.lpstrFile = syFile ;
    strncpy(syFile, default.c_str(), MAX_PATH);
    sfn.nMaxFile = sizeof( syFile );
    sfn.lpstrFilter = filter;
    sfn.nFilterIndex =1;
    sfn.lpstrFileTitle = NULL ;
    sfn.nMaxFileTitle = 0 ;
    sfn.lpstrInitialDir=NULL;

    sfn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOVALIDATE | OFN_HIDEREADONLY;
    if (GetSaveFileNameA( &sfn ) != TRUE)
        return nullptr;

    return syFile;
}

int GetPidByProcessName(const string& processName) 
{
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32)) {
        cerr << "Failed to get first process" << endl;
        CloseHandle(hProcessSnap);
        return 0;
    }

    DWORD pid = 0;
    do
    {
        if (!strcmpi(pe32.szExeFile, processName.c_str())) {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return pid;
}

const char* GetProcessNameByPid(int pid)
{
    static char processName[MAX_PATH];
    auto handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (handle == INVALID_HANDLE_VALUE)
        return nullptr;
    
    auto n = GetProcessImageFileName(handle, processName, MAX_PATH);
    CloseHandle(handle);

    if (n == 0)
        return nullptr;
    
    string name(processName);
    if (name.find_last_of('\\') != string::npos)
        name = name.substr(name.find_last_of('\\') + 1);

    strncpy(processName, name.c_str(), MAX_PATH);
    return processName;
}

shared_ptr<WinProcessNative>
CreateProcessAndSuspend(const string& exefile, const string& args, 
                        SuspendingState state, WinProcessNative::suspend_t& suspend)
{
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFO si = { 0 };
    DEBUG_EVENT de;
    si.cb = sizeof(si);
    string cmdline = exefile + " " + args;

    bool success = false;
    HANDLE hp = INVALID_HANDLE_VALUE;
    auto d1 = defer([&] {
        if (success || hp == INVALID_HANDLE_VALUE)
            return;
        
        TerminateProcess(hp, 1);
    });

    if (state == SUSPEND_ON_NO_SUSPEND)
    {
        if (!CreateProcessA(NULL, (LPSTR)cmdline.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            cerr << "CreateProcess failed: " << GetLastErrorAsString() << endl;
            return nullptr;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        auto process = make_shared<WinProcessNative>(pi.dwProcessId);
        success = true;
        return process;
    }

    if (!CreateProcessA(NULL, (LPSTR)cmdline.c_str(), NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS | DEBUG_PROCESS, NULL, NULL, &si, &pi)) {
        cerr << "CreateProcess failed: " << GetLastError() << endl;
        return nullptr;
    }
    hp = pi.hProcess;

    set<string> ntkernel = { "ntdll.dll", "kernel32.dll" };
    auto mainmod = MemoryMapPEFile(exefile);
    auto imports = mainmod.imports();
    set<string> require_dlls;
    for (auto& i : imports) {
        auto name = i.first;
        if (name.find_last_of('\\') != string::npos)
            name = name.substr(name.find_last_of('\\') + 1);

        std::transform(name.begin(), name.end(), name.begin(), ::tolower);
        require_dlls.insert(name);
    }

    while (true) {
        if (!WaitForDebugEvent(&de, INFINITE)) {
            cerr << "WaitForDebugEvent failed: " << GetLastError() << endl;
            return nullptr;
        }

        if (de.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
            auto filename = GetFilenameFromFileHandle(de.u.LoadDll.hFile);
            if (filename.find_last_of('\\') != string::npos)
                filename = filename.substr(filename.find_last_of('\\') + 1);

            transform(filename.begin(), filename.end(), filename.begin(), ::tolower);
            if (filename.empty()) {
                cerr << "Failed to get filename from file handle" << endl;
                return nullptr;
            }
            std::cout << "  load " << filename << endl;

            if (require_dlls.find(filename) != require_dlls.end())
                require_dlls.erase(require_dlls.find(filename));

            if (ntkernel.find(filename) != ntkernel.end())
                ntkernel.erase(ntkernel.find(filename));

            if (require_dlls.empty()) {
                std::cout << "load all dlls" << endl;
                require_dlls.insert("");

                if (state == SUSPEND_ON_ALL_MODULE_LOADED)
                    break;
            }

            if (ntkernel.empty() && state == SUSPEND_ON_NTDLL_KERNEL32_LOADED)
                break;
        }
        else if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            if (de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
                std::cout << "catch first breakpoint raised by windows" << endl;
                break;
            }
            else {
                cerr << "unexpected exception: exit" << endl;
                return nullptr;
            }
        }
        else if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            cerr << "unexpected: process exited" << endl;
            return nullptr;
        }

        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
    }

    auto process = make_shared<WinProcessNative>(pi.dwProcessId);

    char originChar = '\0';
    WinProcessNative::addr_t entrypoint;
    if (state == SUSPEND_ON_ENTRYPOINT) {
        auto exemod = process->find_module(exefile);
        entrypoint = exemod->baseaddr() + exemod->header().entrypointRVA();
        originChar = process->get_at(entrypoint);
        process->set_at(entrypoint, '\xcc');
        process->flush();
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
    }

    while (state == SUSPEND_ON_ENTRYPOINT) {
        if (!WaitForDebugEvent(&de, INFINITE)) {
            cerr << "WaitForDebugEvent failed: " << GetLastError() << endl;
            return nullptr;
        }

        if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            if (de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
                std::cout << "catch entrypoint breakpoint" << endl;
                auto thandle = OpenThread(THREAD_ALL_ACCESS, FALSE, de.dwThreadId);
                if (thandle == INVALID_HANDLE_VALUE) {
                    cerr << "OpenThread failed: " << GetLastError() << endl;
                    return nullptr;
                }
                auto d1 = defer([&]() { CloseHandle(thandle); });

                PCONTEXT pctx = nullptr;
                DWORD ctxSize = 0;
                if (InitializeContext(nullptr, CONTEXT_CONTROL, &pctx, &ctxSize) ||
                    GetLastError() != ERROR_INSUFFICIENT_BUFFER)
                {
                    cerr << "InitializeContext failed, expect insufficent buffer " << GetLastErrorAsString() << endl;
                    return nullptr;
                };
                shared_ptr<char> ctx_buf(new char[ctxSize], std::default_delete<char[]>());
                if (!InitializeContext(ctx_buf.get(), CONTEXT_CONTROL, &pctx, &ctxSize)) {
                    cerr << "InitializeContext failed: " << GetLastErrorAsString() << endl;
                    return nullptr;
                }
                if (!GetThreadContext(thandle, pctx)) {
                    cerr << "GetThreadContext failed: " << GetLastError() << endl;
                    return nullptr;
                }

#ifdef _WIN64
                pctx->Rip--;
#else
                pctx->Eip--;
#endif 
                
                if (!SetThreadContext(thandle, pctx)) {
                    cerr << "SetThreadContext failed: " << GetLastError() << endl;
                    return nullptr;
                }

                break;
            }
            else {
                cerr << "unexpected exception: exit" << endl;
                return nullptr;
            }
        }
        else if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            cerr << "unexpected: process exited" << endl;
            return nullptr;
        }

        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
    }

    auto s = process->suspendThread();
    if (s == nullptr) {
        cerr << "suspendThread failed: " << GetLastError() << endl;
        return nullptr;
    }

    if (state == SUSPEND_ON_ENTRYPOINT) {
        process->set_at(entrypoint, originChar);
        process->flush();
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
    }
    if(!DebugActiveProcessStop(pi.dwProcessId)) {
        cerr << "DebugActiveProcessStop failed: " << GetLastError() << endl;
        return nullptr;
    }

    suspend = std::move(s);
    success = true;
    return process;
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

string GetFilenameFromFileHandle(HANDLE hFile)
{
    BOOL bSuccess = FALSE;
    char pszFilename[MAX_PATH + 1];
    HANDLE hFileMap;

    DWORD dwFileSizeHi = 0;
    DWORD dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi);

    bool success = false;
    if (dwFileSizeLo == 0 && dwFileSizeHi == 0)
        return "";

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

    if (!success)
        return "";

    return string(pszFilename);
}

string GetLastErrorAsString() {
    DWORD errorMessageID = ::GetLastError();
    if (errorMessageID == 0)
        return std::string(); //No error message has been recorded

    LPSTR messageBuffer = nullptr;
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

    std::string message(messageBuffer, size);

    //Free the buffer.
    LocalFree(messageBuffer);

    return message;
}

vector<PROCESSENTRY32> GetProcessList()
{
    vector<PROCESSENTRY32> ret;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        throw runtime_error("CreateToolhelp32Snapshot failed: " + GetLastErrorAsString());
    auto d1 = defer([&]() { CloseHandle(hSnapshot); });

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe))
        return ret;

    do {
        ret.push_back(pe);
    } while (Process32Next(hSnapshot, &pe));
    return ret;
}