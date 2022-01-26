#if defined(_WIN32) || defined(_WIN64)
#include "process/pe_header.h"
#include "process/win_process_native.h"
#include "process/memory_map_win_page.h"
#include "process/memory_map_module.h"
#include "process/memory_map_section.h"
#include "process/memory_map_stealthy_module.h"
#include "str_utils.h"
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

void WinProcessNative::reopen(DWORD add_desiredAcess) {
    HANDLE ph = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | add_desiredAcess,
                            FALSE, this->process_id);

    if (ph == NULL)
        throw runtime_error("OpenProcess failed");

    this->process_handle = std::shared_ptr<HANDLE>(new HANDLE(ph), [](HANDLE *ph)
                                                    { CloseHandle(*ph); delete ph; });
}

void WinProcessNative::refresh_process()
{
    if (!this->process_handle)
        this->reopen(0);
    auto ph = *this->process_handle;
    this->process_maps.clear();
    this->clear_modules();
    vector<tuple<void*,size_t,string>> modules;

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

    this->add_nomodule_pages();

    auto less_func = [](std::shared_ptr<MemoryMap> &a, const void *base) {
        return reinterpret_cast<void *>(a->baseaddr()) < base;
    };
    vector<shared_ptr<MemoryMap>> module_maps;
    for (auto& module: modules) {
        vector<shared_ptr<MemoryMap>> maps;
       auto module_page = std::lower_bound(
            this->process_maps.begin(), this->process_maps.end(), get<0>(module),
            less_func);

        if (module_page == this->process_maps.end() || 
            reinterpret_cast<void*>((*module_page)->baseaddr()) != get<0>(module))
        {
            cerr << "unexpected module: page not found or incorrect base, continue" << endl;
            continue;
        }

        // FIXME: whether PE header size can be greater than page size
        auto tpage = *module_page;
        maps.push_back(tpage);
        vector<char> pe_buf;
        for (auto c: *tpage) pe_buf.push_back(c);
        PEHeader peheader(pe_buf);
        for (auto& sec: peheader.section_hdrs) {
            void* sec_base = reinterpret_cast<void*>(sec.VirtualAddress + tpage->baseaddr());
            auto first_page = std::lower_bound(
                this->process_maps.begin(), this->process_maps.end(), sec_base,
                less_func);
            void* sec_end = reinterpret_cast<void*>(sec.VirtualAddress + tpage->baseaddr() + sec.Misc.VirtualSize);
            auto end_page = std::lower_bound(
                this->process_maps.begin(), this->process_maps.end(), sec_end,
                less_func);

            if (end_page - first_page > 0) {
                vector<shared_ptr<MemoryMap>> sec_maps(first_page, end_page);
                auto sec_map = shared_ptr<MemoryMap>(new MemoryMapSection((char *)sec.Name, std::move(sec_maps)));
                maps.push_back(sec_map);
            } else {
                cout << std::hex << sec.SizeOfRawData << " " << sec.VirtualAddress  << " " << tpage->baseaddr() << endl;
                cerr << "unexpected module: section '"
                     << get<2>(module) << "@" << sec.Name << "' not found or incorrect base, continue" << endl;
            }
        }
        std::sort(maps.begin(), maps.end(), [](const shared_ptr<MemoryMap> &a, const shared_ptr<MemoryMap> &b) {
            return a->baseaddr() < b->baseaddr();
        });

        auto module_map = shared_ptr<MemoryMap>(new MemoryMapModule(get<2>(module), peheader, std::move(maps)));
        module_maps.push_back(module_map);

        auto module_page_beg = std::lower_bound(
            this->process_maps.begin(), this->process_maps.end(), get<0>(module),
            less_func);
        void* module_end = reinterpret_cast<void*>(reinterpret_cast<size_t>(get<0>(module)) + get<1>(module));
        auto module_page_end = std::lower_bound(
            this->process_maps.begin(), this->process_maps.end(), module_end,
            less_func);
        this->process_maps.erase(module_page_beg, module_page_end);
    }
    for (auto smodule: this->stealthy_modules) {
        auto ml = std::lower_bound(
            this->process_maps.begin(), this->process_maps.end(),
            reinterpret_cast<void*>(smodule.first), less_func
        );
        auto mu = std::lower_bound(
            this->process_maps.begin(), this->process_maps.end(),
            reinterpret_cast<void*>(smodule.first + smodule.second.second), less_func
        );
        auto base = reinterpret_cast<void*>(smodule.first);
        auto mpage = make_shared<MemoryMapWinPage>(this->process_handle, base, smodule.second.second, false);
        auto mmodule = make_shared<MemoryMapStealthyModule>(mpage, smodule.second.first);
        this->process_maps.erase(ml, mu);
        module_maps.push_back(mmodule);
    }

    for (auto& module_map: module_maps) {
        auto mod = std::dynamic_pointer_cast<MapPEModule>(module_map);
        assert(mod && "this map should be pe module");
        this->add_module(mod->module_name(), mod);
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
    const auto pagesize = this->page_size();
    while(VirtualQueryEx(handle, addr, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && mbi.Type != MEM_MAPPED) {
                for(size_t i=0;i<mbi.RegionSize;i+=pagesize) {
                    auto base = reinterpret_cast<void*>(reinterpret_cast<addr_t>(mbi.BaseAddress) + i);
                    size_t size = min(mbi.RegionSize - i, pagesize);
                    auto mmap = std::make_shared<MemoryMapWinPage>(this->process_handle,
                                                                   base, size, false);
                    this->process_maps.push_back(mmap);
                }
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

vector<string> WinProcessNative::get_modules() const {
    vector<string> ans;
    for (auto& module: this->m_modules) {
        ans.push_back(module.first);
    }
    return ans;
}

static string __tolower(const string& str) {
    string res;
    for (auto c: str) res.push_back(tolower(c));
    return res;
}

void WinProcessNative::add_module(const string& name, shared_ptr<MapPEModule> module) {
    if (name.empty())
        throw runtime_error("module name is empty");
    this->m_modules[this->canonicalize_module_name(name)] = module;
}

void WinProcessNative::clear_modules() {
    this->m_modules.clear();
}

string WinProcessNative::canonicalize_module_name(const string& name) {
    return canonicalizeModuleName(name);
}

shared_ptr<MapPEModule> WinProcessNative::find_module(const string& name) {
    auto cname = this->canonicalize_module_name(name);
    auto it = this->m_modules.find(cname);
    if (it == this->m_modules.end())
        return nullptr;
    return it->second;
}

const shared_ptr<MapPEModule> WinProcessNative::find_module(const string& name) const {
    auto _this = const_cast<WinProcessNative*>(this);
    return _this->find_module(name);
}

void WinProcessNative::refresh() {
    this->refresh_process();
}

bool WinProcessNative::write(MemoryMap::addr_t addr, const void* data, size_t size) {
    auto cdata = static_cast<const char*>(data);
    for (size_t i=0;i<size;i++) {
        try {
            this->set_at(addr + i, cdata[i]);
        } catch (exception& e) {
            cerr << "addr = 0x" << hex << addr << ", i = " << i << ", size = " << size << endl;
            cerr << "WinProcessNative::write(): " << e.what() << endl;
            return false;
        }
    }

    try {
        this->flush();
        return true;
    } catch (exception&) {
        return false;
    }
}
bool WinProcessNative::read(MemoryMap::addr_t addr, void* data, size_t size) {
    auto cdata = static_cast<char*>(data);
    for (size_t i=0;i<size;i++) {
        try {
            cdata[i] = this->get_at(addr + i);
        } catch(exception&) {
            return false;
        }
    }

    return true;
}
bool WinProcessNative::write(addr_t addr, vector<char> data) {
    return this->write(addr, data.data(), data.size());
}
vector<char> WinProcessNative::read (addr_t addr, size_t size) {
    vector<char> data(size);
    return this->read(addr, data.data(), size) ? data : vector<char>();
}

size_t WinProcessNative::page_size() const {
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    return info.dwPageSize;
}

bool WinProcessNative::isWow64Process() const {
    auto isWow64 = FALSE;
    auto _this = const_cast<WinProcessNative*>(this);
    return ::IsWow64Process(_this->rawhandle(), &isWow64) && (isWow64 == TRUE);
}

HANDLE WinProcessNative::rawhandle() {
    return *this->process_handle.get();
}

bool WinProcessNative::is_64bit() const {
#ifndef _WIN64
    return false;
#else
    return true;
#endif
}

#endif // _WIN32 || _WIN64