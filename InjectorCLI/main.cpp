#include "process/map_pe_module.h"
#include "process/memory_map_pefile.h"
#include "scylla/charybdis.h"
#include <iostream>
#include <string>
#include <vector>
#include <cxxopts.hpp>
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <set>
#include "./utils.h"
#include "utils.hpp"
using namespace std;

using suspend_t = typename WinProcessNative::suspend_t;

enum SuspendingState {
    SUSPEND_ON_NTDLL_KERNEL32_LOADED,
    SUSPEND_ON_ALL_MODULE_LOADED,
    SUSPEND_ON_SYSTEM_BREAKPOINT,
    SUSPEND_ON_ENTRYPOINT,
};
static suspend_t CreateProcessAndSuspend(const string& cmdline, shared_ptr<WinProcessNative>& process, SuspendingState state)
{
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFO si = { 0 };
    DEBUG_EVENT de;
    si.cb = sizeof(si);

    if (!CreateProcess(NULL, (LPSTR)cmdline.c_str(), NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS | DEBUG_PROCESS, NULL, NULL, &si, &pi)) {
        cerr << "CreateProcess failed: " << GetLastError() << endl;
        return nullptr;
    }
    set<string> ntkernel = { "ntdll.dll", "kernel32.dll" };
    char imageName[MAX_PATH];
    auto pathLen = GetModuleFileNameEx(pi.hProcess, nullptr, imageName, MAX_PATH);
    if (pathLen == 0) {
        cerr << "GetProcessImageFileName failed: " << GetLastError() << endl;
        return nullptr;
    }
    const auto imagePath = string(imageName, pathLen);
    auto mainmod = MemoryMapPEFile(imagePath);
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

    process = make_shared<WinProcessNative>(pi.dwProcessId);

    char originChar = '\0';
    WinProcessNative::addr_t entrypoint;
    if (state == SUSPEND_ON_ENTRYPOINT) {
        auto exemod = process->find_module(imagePath);
        entrypoint = exemod->baseaddr() + exemod->header().entrypointRVA();
        originChar = process->get_at(entrypoint);
        process->set_at(entrypoint, '\xcc');
        process->flush();
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);

        std::cout << "EP: 0x" << std::hex << entrypoint << std::dec << endl;
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

                CONTEXT ctx = { 0 };
                if (!GetThreadContext(thandle, &ctx)) {
                    cerr << "GetThreadContext failed: " << GetLastError() << endl;
                    return nullptr;
                }

cout << "ctx.Eip: " << std::hex << ctx.Eip << std::dec << endl;
#ifdef _WIN64
                ctx.Rip--;
#else
                ctx.Eip--;
#endif 
                
                cout << "  set eip to " << std::hex << ctx.Eip << std::dec << endl;
                if (!SetThreadContext(thandle, &ctx)) {
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

    auto suspend = process->suspendThread();

    if (state == SUSPEND_ON_ENTRYPOINT) {
        process->set_at(entrypoint, originChar);
        process->flush();
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
    }
    if(!DebugActiveProcessStop(pi.dwProcessId)) {
        cerr << "DebugActiveProcessStop failed: " << GetLastError() << endl;
        return nullptr;
    }

    return suspend;
}

int main(int argc, char* argv[])
{
    string yaml_config;
    string process_name;
    int pid = 0;
    string new_process_cmdline;
    vector<string> new_process_command_line;

    cxxopts::Options options(argv[0], "A command line interface for Injector");
    options.set_width(100);

    options.add_options()
        ( "c,config",    "configuration file with yaml format", cxxopts::value<string>(yaml_config)->default_value("scylla.yaml"),  "<path>" )
        ( "p,pid",       "pid of target process",  cxxopts::value<int>(pid),  "<pid>" )
        ( "name",        "process name of target process", cxxopts::value<string>(process_name), "<name>" )
        ( "new",         "new process command line", cxxopts::value<string>(new_process_cmdline), "<path>" )
        ( "h,help",      "print help");

    cxxopts::ParseResult result;
    try {
        result = options.parse(argc, argv);
    } catch (std::exception e) {
        std::cout << "bad arguments" << endl;
        std::cout << options.help() << endl;
        return 1;
    }

    if (result.count("help")) {
        std::cout << options.help() << endl;
        return 0;
    }

    if (result.count("pid") == 0 &&
        result.count("name") == 0 &&
        result.count("new") == 0) 
    {
        cerr << "no target process specified" << endl;
        return 1;
    }

    int allspec = result.count("pid") + result.count("name") + result.count("new");
    if (allspec != 1) {
        cerr << "only and at least one target process should be specified" << endl;
        return 1;
    }

    if (!process_name.empty()) {
        pid = GetPidByProcessName(process_name);
        if (pid == 0) {
            cerr << "failed to get pid of " << process_name << endl;
            return 1;
        }
    }

    std::shared_ptr<WinProcessNative> process;
    suspend_t suspend_state;
    if (pid > 0) {
        try {
            process = std::make_shared<WinProcessNative>(pid);
        } catch (std::exception& e) {
            cerr << "failed to get process " << pid << ": " << e.what() << endl;
            return 1;
        }
        
        suspend_state = process->suspendThread();
        if (!suspend_state) {
            cerr << "failed to suspend target process" << endl;
            return 1;
        }
    }

    if (!new_process_cmdline.empty()) {
        if (!SetDebugPrivileges()) {
            cerr << "failed to set debug privileges" << endl;
            return 1;
        }

        if (!EnablePrivilege(SE_DEBUG_NAME, TRUE)) {
            cerr << "failed to enable debug privilege" << endl;
            return 1;
        }

        try {
            suspend_state = CreateProcessAndSuspend(new_process_cmdline, process, SUSPEND_ON_ENTRYPOINT);
        } catch (std::exception& e) {
            cerr << "failed to create process: " << e.what() << endl;
            return  1;
        }

        if (!suspend_state) {
            cerr << "failed to create new process" << endl;
            return 1;
        }
    }

    scylla::Charybdis charybdis(process);
    try {
        charybdis.doit_file(yaml_config);
    } catch (std::exception& e) {
        cerr << "failed to loading config: " << e.what() << endl;
        return 1;
    }

    std::cout << "resuming target process" << endl;
    if (!process->resumeThread(std::move(suspend_state))) {
        cerr << "failed to resume target process" << endl;
        return 1;
    }

    string outMsg;
    for (;;cin >> outMsg) {
        std::cout << "enter 'exit' to exit" << endl;

        if (outMsg == "exit")
            break;
    }
    return 0;
}