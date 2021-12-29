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
    do {
        std::cout << "ENTER 'exit' TO EXIT" << endl;
    } while ((cin >> outMsg), !cin.fail() && outMsg != "exit");
    return 0;
}