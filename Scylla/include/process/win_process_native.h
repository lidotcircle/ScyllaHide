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

    void refresh_process();
    void add_nomodule_pages();

public:
    WinProcessNative(int pid);

    virtual size_t map_count() const override;
    virtual std::shared_ptr<MemoryMap> get_map(size_t index) override;

    const ModuleMapType& get_modules() const;

    void refresh();
};

#endif // _WIN_PROCESS_NATIVE_H_