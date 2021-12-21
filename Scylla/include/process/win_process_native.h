#ifndef _WIN_PROCESS_NATIVE_H_
#define _WIN_PROCESS_NATIVE_H_

#include "memory_map_collection.h"
#include <vector>
#include <memory>
#include <map>
#include <type_traits>
#include <windows.h>

class MapPEModule;
class PagePool;
class HookHandle {
public:
    virtual void* trampoline() = 0;
    virtual ~HookHandle() = default;
};

class WinProcessNative : public MemoryMapCollection
{
public:
    using ProcessHandle = std::shared_ptr<HANDLE>;
    using ModuleMapType = std::map<std::string,std::shared_ptr<MapPEModule>>;
    using addr_t  = typename MemoryMap::addr_t;
    using hook_t  = std::unique_ptr<HookHandle>;

private:
    int process_id;
    ProcessHandle process_handle;
    std::vector<std::shared_ptr<MemoryMap>> process_maps;
    std::map<DWORD,std::shared_ptr<PagePool>> allocated_pages;
    std::map<addr_t,std::pair<std::string,size_t>> stealthy_modules;
    ModuleMapType m_modules;

    std::string canonicalize_module_name(const std::string& module_name);
    void clear_modules();
    void add_module(const std::string& module_name, std::shared_ptr<MapPEModule> module);
    void refresh_process();
    void add_nomodule_pages();

    void inject_dll_stealthy   (const std::string& dll_path);
    void inject_dll_loadlibrary(const std::string& dll_path);

public:
    WinProcessNative(int pid);

    virtual size_t map_count() const override;
    virtual std::shared_ptr<MemoryMap> get_map(size_t index) override;

    std::vector<std::string> get_modules() const;
    std::shared_ptr<MapPEModule>       find_module(const std::string& name);
    const std::shared_ptr<MapPEModule> find_module(const std::string& name) const;

    void* malloc(size_t size, size_t alignment = 1, DWORD protect = PAGE_EXECUTE_READWRITE);
    void  free(void* ptr);
    void  free_all();

    bool write(addr_t addr, const void* data, size_t size);
    bool read (addr_t addr, void* data, size_t size);
    bool write(addr_t addr, std::vector<char> data);
    std::vector<char> read (addr_t addr, size_t size);

    inline bool write(void* addr, const void* data, size_t size) {return this->write(reinterpret_cast<MemoryMap::addr_t>(addr), data, size);}
    inline bool read (void* addr, void* data, size_t size) {return this->read (reinterpret_cast<MemoryMap::addr_t>(addr), data, size);}
    inline bool write(void* addr, std::vector<char> data) {return this->write(reinterpret_cast<MemoryMap::addr_t>(addr), data);}
    inline std::vector<char> read(void* addr, size_t size) {return this->read (reinterpret_cast<MemoryMap::addr_t>(addr), size);}

    size_t page_size() const;

    bool isWow64Process() const;
    bool is_64bit() const;
    HANDLE rawhandle();
    void reopen(DWORD add_desiredAcess);

    hook_t hook(addr_t original, addr_t hook);
    bool   unhook(hook_t hook);
    inline hook_t hook(void* original, void* hook) {return this->hook(reinterpret_cast<addr_t>(original), reinterpret_cast<addr_t>(hook));}

    void inject_dll(const std::string& dll_path, bool stealthy);

    void refresh();
};

using WinProcess_t = std::shared_ptr<WinProcessNative>;

#endif // _WIN_PROCESS_NATIVE_H_