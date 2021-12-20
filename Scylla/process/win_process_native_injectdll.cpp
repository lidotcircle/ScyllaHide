#include "process/memory_map_stealthy_module.h"
#include "process/win_process_native.h"
#include "process/memory_map_pefile.h"
#include "process/memory_map_win_page.h"
#include <algorithm>
#include <memory>
#include <string>
#include <stdexcept>
using namespace std;


void WinProcessNative::inject_dll(const string& dll_path, bool stealthy) {
    if (stealthy)
        this->inject_dll_stealthy(dll_path);
    else
        this->inject_dll_loadlibrary(dll_path);
}

void WinProcessNative::inject_dll_stealthy(const string& dll_path) {
    MemoryMapPEFile dll_map(dll_path);

    if (dll_map.header().is_64bit() != this->is_64bit())
        throw runtime_error("DLL is not compatible with process");

    auto& modules = this->get_modules();
    auto& imports = dll_map.imports();
    for (auto& import : imports) {
        auto& dllname = import.first;
        auto mod = modules.find(dllname);

        if (mod == modules.end())
            throw runtime_error("stealthy injection DLL not found: " + dllname);

        auto modmap = mod->second;
        auto modbase = modmap->baseaddr();
        for (auto& func : import.second) {
            addr_t addr;
            if (func.first.is_ordinal()) {
                addr = modmap->resolve_export(func.first.ordinal()) + modbase;
            } else {
                addr = modmap->resolve_export(func.first.symbolname()) + modbase;
            }

            if (this->is_64bit()) {
                this->set_u64(func.second, addr);
            } else {
                this->set_u32(func.second, addr);
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

    this->stealthy_modules[dll_base] = make_pair(dll_path, dll_map.size());
    auto page = std::make_shared<MemoryMapWinPage>(this->process_handle, addr,
                                                   dll_map.size(), false);
    auto modulen = std::make_shared<MemoryMapStealthyModule>(page, dll_path);
    this->modules[dll_path] = modulen;
    this->process_maps.push_back(modulen);

    std::sort(this->process_maps.begin(), this->process_maps.end(),
              [](const std::shared_ptr<MemoryMap>& a, const std::shared_ptr<MemoryMap>& b) {
                  return a->baseaddr() < b->baseaddr();
              });
}

void WinProcessNative::inject_dll_loadlibrary(const string& dllpath) {
    throw runtime_error("not implemented");
}