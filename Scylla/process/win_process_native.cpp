#if defined(_WIN32) || defined(_WIN64)
#include "pe_header.h"
#include "process/win_process_native.h"
#include "process/memory_map_win_page.h"
#include "process/memory_map_module.h"
#include "process/memory_map_section.h"
#include <stdexcept>
#include <Windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <algorithm>
#include <iostream>
#include <assert.h>
using namespace std;


WinProcessNative::WinProcessNative(int pid): process_id(pid) {
    this->refresh_process();
}

void WinProcessNative::refresh_process()
{
    HANDLE ph = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
                             FALSE, this->process_id );

    if (ph == NULL)
        throw runtime_error("OpenProcess failed");

    this->process_handle = std::shared_ptr<HANDLE>(new HANDLE(ph), [](HANDLE* ph) { CloseHandle(*ph); delete ph;});
    this->process_maps.clear();
    this->modules.clear();
    vector<tuple<void*,size_t,string>> modules;


#if defined(_WIN64)
    // List modules on a 64 bit machine. A 64 bit machine is assumed to be Windows Vista+
    HMODULE hMods[2048];
    DWORD cbNeeded;
    unsigned int i;

    if (!EnumProcessModulesEx(ph, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL))
        throw runtime_error("EnumProcessModulesEx failed");

    for ( i = 0; i < (cbNeeded / sizeof(HMODULE)); i++ )
    {
        MODULEINFO info;
        if (GetModuleInformation( ph, hMods[i], &info, sizeof(MODULEINFO))) {
            char name[2048];
            name[0] = 0;
            GetModuleFileNameExA(ph, hMods[i], name, sizeof(name));
            modules.push_back(make_tuple(info.lpBaseOfDll, info.SizeOfImage, string(name)));
        } else {
            throw runtime_error("GetModuleInformation failed");
        }
    }

#elif defined(_WIN32)

    HANDLE hSnapshot=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, this->process_id);
    if ( hSnapshot == INVALID_HANDLE_VALUE )
    {
        throw runtime_error("CreateToolhelp32Snapshot failed");
    }

    MODULEENTRY32 tmpModule;
    tmpModule.dwSize = sizeof(MODULEENTRY32);
    if( Module32First(hSnapshot, &tmpModule) )
    {
        modules.push_back(make_tuple(tmpModule.modBaseAddr, tmpModule.modBaseSize, string(tmpModule.szModule)));

        tmpModule.dwSize = sizeof(MODULEENTRY32);
        while(Module32Next(hSnapshot,&tmpModule))
        {
            modules.push_back(make_tuple(tmpModule.modBaseAddr, tmpModule.modBaseSize, string(tmpModule.szModule)));
        }
    }
#endif // _WIN64

    this->add_nomodule_pages();

    vector<shared_ptr<MemoryMap>> module_maps;
    for (auto& module: modules) {
        vector<shared_ptr<MemoryMap>> maps;

        auto lb_func = [](std::shared_ptr<MemoryMap> &a, const void *base) {
            return reinterpret_cast<void *>(a->baseaddr()) < base;
        };
        auto ub_func = [](const void* base, std::shared_ptr<MemoryMap> &a) {
            return base < reinterpret_cast<void *>(a->baseaddr());
        };
        auto module_page = std::lower_bound(
            this->process_maps.begin(), this->process_maps.end(), get<0>(module),
            lb_func);

        if (module_page == this->process_maps.end() || 
            reinterpret_cast<void*>((*module_page)->baseaddr()) != get<0>(module))
        {
            cerr << "unexpected module: page not found or incorrect base, continue" << endl;
            continue;
        }

        auto tpage = *module_page;
        auto buf = std::shared_ptr<char>(new char[tpage->size()], std::default_delete<char[]>());
        std::copy(tpage->begin(), tpage->end(), buf.get());

        maps.push_back(tpage);
        PEHeader peheader(buf, tpage->size());
        for (auto& sec: peheader.section_hdrs) {
            void* sec_base = reinterpret_cast<void*>(sec.VirtualAddress + tpage->baseaddr());
            auto first_page = std::lower_bound(
                this->process_maps.begin(), this->process_maps.end(), sec_base,
                lb_func);
            void* sec_end = reinterpret_cast<void*>(sec.VirtualAddress + tpage->baseaddr() + sec.SizeOfRawData);
            auto end_page = std::lower_bound(
                this->process_maps.begin(), this->process_maps.end(), sec_end,
                lb_func);

            if (end_page - first_page > 0) {
                vector<shared_ptr<MemoryMap>> sec_maps(first_page, end_page);
                auto sec_map = shared_ptr<MemoryMap>(new MemoryMapSection((char *)sec.Name, std::move(sec_maps)));
                maps.push_back(sec_map);
            }
        }
        std::sort(maps.begin(), maps.end(), [](const shared_ptr<MemoryMap> &a, const shared_ptr<MemoryMap> &b) {
            return a->baseaddr() < b->baseaddr();
        });

        auto module_map = shared_ptr<MemoryMap>(new MemoryMapModule(get<2>(module), std::move(maps)));
        module_maps.push_back(module_map);

        auto module_page_beg = std::lower_bound(
            this->process_maps.begin(), this->process_maps.end(), get<0>(module),
            lb_func);
        void* module_end = reinterpret_cast<void*>(reinterpret_cast<size_t>(get<0>(module)) + get<1>(module));
        auto module_page_end = std::lower_bound(
            this->process_maps.begin(), this->process_maps.end(), module_end,
            lb_func);
        this->process_maps.erase(module_page_beg, module_page_end);
    }

    for (auto& module_map: module_maps) {
        auto mod = std::dynamic_pointer_cast<MemoryMapModule>(module_map);
        assert(mod && "this map should be module");
        this->modules[mod->module_name()] = mod;
        this->process_maps.push_back(module_map);
    }

    std::sort(this->process_maps.begin(), this->process_maps.end(), [](const shared_ptr<MemoryMap> &a, const shared_ptr<MemoryMap> &b) {
        return a->baseaddr() < b->baseaddr();
    });
}

void WinProcessNative::add_nomodule_pages()
{
    auto handle = *this->process_handle.get();
    MEMORY_BASIC_INFORMATION mbi;
    LPCVOID addr = nullptr;

    this->process_maps.clear();
    while(VirtualQueryEx(handle, addr, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && mbi.Type != MEM_MAPPED) {
                auto mmap = std::make_shared<MemoryMapWinPage>(this->process_handle,
                                                               mbi.BaseAddress,
                                                               mbi.RegionSize, false);
                this->process_maps.push_back(mmap);
            }

        addr = reinterpret_cast<LPCVOID>(reinterpret_cast<size_t>(mbi.BaseAddress) + mbi.RegionSize);
    }

    std::sort(this->process_maps.begin(),
              this->process_maps.end(),
              [](const std::shared_ptr<MemoryMap>& a, const std::shared_ptr<MemoryMap>& b) {
        return a->baseaddr() < b->baseaddr();
    });
}

size_t WinProcessNative::map_count() const {
    return this->process_maps.size();
}

std::shared_ptr<MemoryMap> WinProcessNative::get_map(size_t index) {
    if (index >= this->process_maps.size())
        throw runtime_error("index out of range");

    return this->process_maps[index];
}

const WinProcessNative::ModuleMapType& WinProcessNative::get_modules() const {
    return this->modules;
}

void WinProcessNative::refresh() {
    this->refresh_process();
}

#endif // _WIN32 || _WIN64