#include "process/map_pe_module.h"
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
using namespace std;

using suspend_t = typename WinProcessNative::suspend_t;

static suspend_t CreateProcessAndSuspend(const string& cmdline, shared_ptr<WinProcessNative>& process)
{
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFO si = { 0 };
    DEBUG_EVENT de;
    si.cb = sizeof(si);

    if (!CreateProcess(NULL, (LPSTR)cmdline.c_str(), NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS | DEBUG_PROCESS, NULL, NULL, &si, &pi)) {
        cerr << "CreateProcess failed: " << GetLastError() << endl;
        return nullptr;
    }
    process = make_shared<WinProcessNative>(pi.dwProcessId);
    auto ms = process->get_modules();
    if (ms.size() != 1) {
        cerr << "Expected 1 module, got " << ms.size() << endl;
        return nullptr;
    }
    auto mainmod = process->find_module(ms[0]);
    if (!mainmod) {
        cerr << "Failed to find main module" << endl;
        return nullptr;
    }

    auto imports = mainmod->imports();
    set<string> require_dlls;
    for (auto& i : imports) {
        auto name = i.first;
        if (name.find_last_of('\\') != string::npos)
            name = name.substr(name.find_last_of('\\') + 1);

        require_dlls.insert(name);
    }
    /*
    require_dlls = {
        "kernel32.dll",
        "ntdll.dll",
    };
    */

    while (true) {
        if (!WaitForDebugEvent(&de, INFINITE)) {
            cerr << "WaitForDebugEvent failed: " << GetLastError() << endl;
            return nullptr;
        }

        if (de.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
            auto filename = GetFilenameFromFileHandle(de.u.LoadDll.hFile);
            if (filename.find_last_of('\\') != string::npos)
                filename = filename.substr(filename.find_last_of('\\') + 1);

            if (filename.empty()) {
                cerr << "Failed to get filename from file handle" << endl;
                return nullptr;
            }
            std::cout << "  load " << filename << endl;

            if (require_dlls.find(filename) != require_dlls.end())
                require_dlls.erase(require_dlls.find(filename));

            if (require_dlls.empty())
                break;
        }
        else if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            cerr << "unexpected: process exited" << endl;
            return nullptr;
        }

        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
    }

    auto suspend = process->suspendThread();
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
        cout << "bad arguments" << endl;
        cout << options.help() << endl;
        return 1;
    }

    if (result.count("help")) {
        cout << options.help() << endl;
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
        process = std::make_shared<WinProcessNative>(pid);
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

        suspend_state = CreateProcessAndSuspend(new_process_cmdline, process);
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

    string outMsg;
    for (;;cin >> outMsg) {
        cout << "enter 'exit' to exit" << endl;

        if (outMsg == "exit")
            break;
    }
    return 0;
}