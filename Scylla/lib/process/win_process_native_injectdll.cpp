#include "process/memory_map_stealthy_module.h"
#include "process/win_process_native.h"
#include "process/memory_map_pefile.h"
#include "process/memory_map_win_page.h"
#include "utils.hpp"
#include <fileapi.h>
#include <algorithm>
#include <memory>
#include <string>
#include <stdexcept>
#include <fstream>
#include <iostream>
using namespace std;


static string get_temp_path() {
    char buf[MAX_PATH];
    GetTempPathA(MAX_PATH, buf);
    return string(buf);
}

void WinProcessNative::inject_dll(const string& dll_path, bool stealthy) {
    if (this->find_module(dll_path))
        throw runtime_error("inject_dll(): DLL already exists");

    if (stealthy)
        this->inject_dll_stealthy(dll_path);
    else
        this->inject_dll_loadlibrary(dll_path);
}

void WinProcessNative::inject_dll(const unsigned char* buffer, size_t size, const string& dllname, bool stealthy) {
    if (this->find_module(dllname))
        throw runtime_error("inject_dll(): DLL already exists");

    if (stealthy) {
        this->inject_dll_stealthy(buffer, size, dllname);
    } else {
        auto modname = dllname;
        if (modname.find_last_of('\\') != string::npos)
            modname = modname.substr(modname.find_last_of('\\') + 1);
        if (modname.find_last_of('/') != string::npos)
            modname = modname.substr(modname.find_last_of('/') + 1);

        auto modfile = get_temp_path() + "\\" + modname;
        ofstream file(modfile, ios::binary | ios::out);
        file.write((const char*)buffer, size);
        file.close();
        this->inject_dll_loadlibrary(modfile);
    }
}

void WinProcessNative::inject_dll_stealthy(const unsigned char* buffer,
                                           size_t bufsize, const string& dllname)
{
    vector<char> buf(buffer, buffer + bufsize);
    MemoryMapPEFile dll_map(buf);

    if (dll_map.header().is_64bit() != this->is_64bit())
        throw runtime_error("DLL is not compatible with process");

    auto& imports = dll_map.imports();
    for (auto& import : imports) {
        auto& dllname = import.first;
        auto modmap = this->find_module(dllname);
        if (!modmap)
            throw runtime_error("stealthy injection DLL not found: " + dllname);

        auto modbase = modmap->baseaddr();
        for (auto& func : import.second) {
            addr_t addr;
            if (func.first.is_ordinal()) {
                addr = modmap->resolve_export(func.first.ordinal()) + modbase;
            } else {
                addr = modmap->resolve_export(func.first.symbolname()) + modbase;
            }

            if (this->is_64bit()) {
                dll_map.set_u64(func.second, addr);
            } else {
                dll_map.set_u32(func.second, addr);
            }
        }
    }

    auto addr = this->malloc(dll_map.size(), 1, PAGE_EXECUTE_READWRITE);
    addr_t dll_base = reinterpret_cast<addr_t>(addr);
    dll_map.base_relocate(dll_base);

    if (!this->write(addr, dll_map.data_ptr(), dll_map.size())) {
        this->free(addr);
        throw runtime_error("failed to write DLL to process");
    }

    this->stealthy_modules[dll_base] = make_pair(dllname, dll_map.size());
    auto page = std::make_shared<MemoryMapWinPage>(this->process_handle, addr,
                                                   dll_map.size(), false);
    auto modulen = std::make_shared<MemoryMapStealthyModule>(page, dll_map.header(), dllname);
    this->add_module(dllname, modulen);
    this->process_maps.push_back(modulen);

    std::sort(this->process_maps.begin(), this->process_maps.end(),
              [](const std::shared_ptr<MemoryMap>& a, const std::shared_ptr<MemoryMap>& b) {
                  return a->baseaddr() < b->baseaddr();
              });
}

void WinProcessNative::inject_dll_stealthy(const string& dll_path) {
    ifstream file(dll_path, ios::binary | ios::ate);

    if (!file.is_open())
        throw runtime_error("Failed to open file");

    size_t size = file.tellg();
    file.seekg(0, ios::beg);
    vector<char> buf(size);
    file.read(buf.data(), size);

    this->inject_dll_stealthy((unsigned char*)buf.data(), size, dll_path);
}

static string GetLastErrorAsString() {
    DWORD errorMessageID = ::GetLastError();
    if (errorMessageID == 0)
        return std::string();

    LPSTR messageBuffer = nullptr;
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                 NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

    std::string message(messageBuffer, size);

    // Free the buffer.
    LocalFree(messageBuffer);

    return message;
}

void WinProcessNative::inject_dll_loadlibrary(const string& dllpath) {
    char buf[MAX_PATH];
    if (GetFullPathNameA(dllpath.c_str(), MAX_PATH, buf, nullptr) == 0) {
        auto error = GetLastErrorAsString();
        throw runtime_error("inject_dll_loadlibrary(): Failed to get full path name, " + error);
    }
    string dllfullpath = buf;
    auto ptr = this->malloc(dllfullpath.size() + 1, 1, PAGE_READONLY);
    auto d1 = defer([&]() { if (ptr) this->free(ptr); });
    if (ptr == 0)
        throw runtime_error("inject_dll_loadlibrary(): Failed to allocate memory");

    if (!this->write(ptr, dllfullpath.c_str(), dllfullpath.size() + 1))
        throw runtime_error("inject_dll_loadlibrary(): Failed to write memory");
    
    auto ptr_loadlibraryA = LoadLibraryA;
    auto thread = CreateRemoteThread(this->rawhandle(), nullptr, 0,
                                     (LPTHREAD_START_ROUTINE)ptr_loadlibraryA, ptr, 0, nullptr);
    if (thread == 0)
        throw runtime_error("inject_dll_loadlibrary(): Failed to create remote thread");
    WaitForSingleObject(thread, INFINITE);
    this->refresh_process();

    if (!this->find_module(dllfullpath))
        throw runtime_error("inject_dll_loadlibrary(): Failed to inject DLL");
}