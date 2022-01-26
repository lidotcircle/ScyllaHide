#include "process/pe_header.h"
#include "process/win_process_native.h"
#include "process/memory_map_win_page.h"
#include "process/memory_map_module.h"
#include "str_utils.h"
#include <stdexcept>
#include <Windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <algorithm>
#include <iostream>
#include <assert.h>
using namespace std;


static bool is_2pow(size_t n) {
    return (n & (n - 1)) == 0;
}

static char* align_ptr(char* ptr, size_t align) {
    if (!is_2pow(align))
        throw runtime_error("align must be a power of 2");

    size_t pv = reinterpret_cast<size_t>(ptr);
    return (char*)((pv + align - 1) & ~(align - 1));
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
            if (lb == allocations.end()){
                if (!allocations.empty()) lb--;
            } else if (lb->first > ptr) {
                if (lb == allocations.begin())
                    lb = allocations.end();
                else
                    lb--;
            }
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

            assert(allocations.find(ptr) == allocations.end());
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
