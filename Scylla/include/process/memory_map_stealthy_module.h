#ifndef _MEMORY_MAP_STEALTHY_MODULE_H_
#define _MEMORY_MAP_STEALTHY_MODULE_H_

#include "map_pe_module.h"
#include "memory_map_win_page.h"
#include <vector>
#include <memory>
using namespace std;

class MemoryMapStealthyModule : public MapPEModule
{
public:
    using addr_t = typename MapPEModule::addr_t;

private:
    std::string dll_path;
    std::shared_ptr<MemoryMapWinPage> page;

public:
    MemoryMapStealthyModule() = delete;
    MemoryMapStealthyModule(std::shared_ptr<MemoryMapWinPage> page, const std::string& modname);
    MemoryMapStealthyModule(std::shared_ptr<MemoryMapWinPage> page, PEHeader header, const std::string& modname);

    virtual addr_t baseaddr() const override;
    virtual size_t size() const override;

    virtual char get_at(addr_t index) const override;
    virtual void set_at(addr_t index, char value) override;

    virtual void flush() override;

    const std::string& module_name() const;
};

#endif // _MEMORY_MAP_STEALTHY_MODULE_H_