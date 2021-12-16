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

static char* align_ptr(char* ptr, size_t align) {
    return (char*)(((size_t)ptr + align - 1) & ~(align - 1));
}

static size_t round_to_2pow(size_t size) {
    size_t ret = 1;
    while (ret < size) {
        ret <<= 1;
    }
    return ret;
}

class AllocatedPage {
private:
    shared_ptr<MemoryMapWinPage> page;
    size_t max_size; // TODO
    map<char*,size_t> allocations;

public:
    AllocatedPage(shared_ptr<MemoryMapWinPage> page): page(page) {
        max_size = page->size();
    }
    void* malloc(size_t size, size_t align) {
        auto ptr = static_cast<char*>(reinterpret_cast<void*>(page->baseaddr()));
        if (reinterpret_cast<uintptr_t>(ptr) % align != 0)
            return nullptr;

        auto ptr_end = ptr + page->size();
        for (;ptr < ptr_end; ptr = align_ptr(ptr, align)) {
            auto lb = allocations.lower_bound(ptr);
            if (lb != allocations.end() && lb->first + lb->second > ptr) {
                ptr = lb->first + lb->second;
                continue;
            }

            size_t holesize = ptr_end - ptr;
            auto ub = allocations.upper_bound(ptr);
            if (ub != allocations.end())
                holesize = ub->first - ptr;

            if (holesize < size) {
                ptr += holesize;
                continue;
            }

            allocations[ptr] = size;
            return ptr;
        }

        return nullptr;
    }
    bool free(void* _ptr) {
        auto ptr = static_cast<char*>(_ptr);

        if (allocations.find(ptr) == allocations.end())
            return false;

        allocations.erase(ptr);
        return true;
    }
    void free_all() {
        this->allocations.clear();
        this->max_size = page->size();
    }
    size_t maxsize() {
        return this->max_size;
    }
};

class PagePool {
private:
    DWORD protection;
    shared_ptr<HANDLE> process_handle;
    vector<AllocatedPage> pages;

public:
    PagePool(shared_ptr<HANDLE> phandle, DWORD protection): 
        process_handle(phandle), protection(protection) {}
    
    void* malloc(size_t size, size_t alignment, shared_ptr<MemoryMapWinPage>& newpage) {
        for (auto& page: pages) {
            auto ptr = page.malloc(size, alignment);
            if (ptr)
                return ptr;
        }

        size_t pagesize = round_to_2pow(size);
        if (pagesize < 0x4096)
            pagesize = 0x4096;
        auto base = VirtualAllocEx(*process_handle.get(), nullptr, pagesize, MEM_COMMIT | MEM_RESERVE, protection);
        if (base) {
            auto page = make_shared<MemoryMapWinPage>(this->process_handle, base, pagesize, false);
            newpage = page;
            pages.push_back(AllocatedPage(page));
            return pages.back().malloc(size, alignment);
        }

        return nullptr;
    }

    bool free(void* ptr) {
        for (auto& page: pages) {
            if (page.free(ptr))
                return true;
        }

        return false;
    }

    /* TODO */
    void free_all() {
        for (auto& page: pages) {
            page.free_all();
        }
        pages.clear();
    }
};


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

        auto less_func = [](std::shared_ptr<MemoryMap> &a, const void *base) {
            return reinterpret_cast<void *>(a->baseaddr()) < base;
        };
       auto module_page = std::lower_bound(
            this->process_maps.begin(), this->process_maps.end(), get<0>(module),
            less_func);

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
                less_func);
            void* sec_end = reinterpret_cast<void*>(sec.VirtualAddress + tpage->baseaddr() + sec.SizeOfRawData);
            auto end_page = std::lower_bound(
                this->process_maps.begin(), this->process_maps.end(), sec_end,
                less_func);

            if (end_page - first_page > 0) {
                vector<shared_ptr<MemoryMap>> sec_maps(first_page, end_page);
                auto sec_map = shared_ptr<MemoryMap>(new MemoryMapSection((char *)sec.Name, std::move(sec_maps)));
                maps.push_back(sec_map);
            } else {
                cerr << "unexpected module: section '"
                     << get<2>(module) << "@" << sec.Name << "' not found or incorrect base, continue" << endl;
            }
        }
        std::sort(maps.begin(), maps.end(), [](const shared_ptr<MemoryMap> &a, const shared_ptr<MemoryMap> &b) {
            return a->baseaddr() < b->baseaddr();
        });

        auto module_map = shared_ptr<MemoryMap>(new MemoryMapModule(get<2>(module), std::move(maps)));
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

void* WinProcessNative::malloc(size_t size, size_t alignment, DWORD protect) {
    if (alignment == 0)
        alignment = 1;

    if (this->allocated_pages.find(protect) == this->allocated_pages.end())
        this->allocated_pages[protect] = make_shared<PagePool>(this->process_handle, protect);
    
    shared_ptr<MemoryMapWinPage> page;
    auto ptr = this->allocated_pages[protect]->malloc(size, alignment, page);
    if (page) {
        this->process_maps.push_back(page);
        std::sort(this->process_maps.begin(), this->process_maps.end(), [](const shared_ptr<MemoryMap> &a, const shared_ptr<MemoryMap> &b) {
            return a->baseaddr() < b->baseaddr();
        });
    }
    return ptr;
}
void  WinProcessNative::free(void* ptr) {
    for (auto& p: this->allocated_pages) {
        if (p.second->free(ptr))
            return;
    }

    throw runtime_error("WinProcessNative::free(): invalid pointer");
}
void  WinProcessNative::free_all() {
    for (auto& p: this->allocated_pages) {
        p.second->free_all();
    }
}

bool WinProcessNative::write(MemoryMap::addr_t addr, const void* data, size_t size) {
    auto cdata = static_cast<const char*>(data);
    for (size_t i=0;i<size;i++) {
        try {
            this->set_at(addr + i, cdata[i]);
        } catch (runtime_error&) {
            return false;
        }
    }
    this->flush();
    return true;
}
bool WinProcessNative::read(MemoryMap::addr_t addr, void* data, size_t size) {
    auto cdata = static_cast<char*>(data);
    for (size_t i=0;i<size;i++) {
        try {
            cdata[i] = this->get_at(addr + i);
        } catch(runtime_error&) {
            return false;
        }
    }

    return true;
}

HANDLE WinProcessNative::rawhandle() {
    return *this->process_handle.get();
}

#endif // _WIN32 || _WIN64