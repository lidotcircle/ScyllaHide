#ifndef _WIN_PROCESS_NATIVE_H_
#define _WIN_PROCESS_NATIVE_H_

#include "memory_map_collection.h"
#include <vector>
#include <memory>
#include <map>
#include <type_traits>
#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#else
typedef int HANDLE;
#endif // defined(_WIN32) || defined(_WIN64)

class MemoryMapModule;
class PagePool;

class WinProcessNative : public MemoryMapCollection
{
public:
    using ProcessHandle = std::shared_ptr<HANDLE>;
    using ModuleMapType = std::map<std::string,std::shared_ptr<MemoryMapModule>>;

private:
    int process_id;
    ProcessHandle process_handle;
    std::vector<std::shared_ptr<MemoryMap>> process_maps;
    ModuleMapType modules;
    std::map<DWORD,std::shared_ptr<PagePool>> allocated_pages;

    void refresh_process();
    void add_nomodule_pages();

public:
    WinProcessNative(int pid);

    virtual size_t map_count() const override;
    virtual std::shared_ptr<MemoryMap> get_map(size_t index) override;

    const ModuleMapType& get_modules() const;

    void* malloc(size_t size, size_t alignment = 1, DWORD protect = PAGE_EXECUTE_READWRITE);
    void  free(void* ptr);
    void  free_all();

    bool write(MemoryMap::addr_t addr, const void* data, size_t size);
    bool read (MemoryMap::addr_t addr, void* data, size_t size);

    inline bool write(void* addr, const void* data, size_t size) {return this->write(reinterpret_cast<MemoryMap::addr_t>(addr), data, size);}
    inline bool read (void* addr, void* data, size_t size) {return this->read (reinterpret_cast<MemoryMap::addr_t>(addr), data, size);}

    HANDLE rawhandle();

    void refresh();
};

#endif // _WIN_PROCESS_NATIVE_H_