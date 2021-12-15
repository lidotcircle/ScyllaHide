#ifndef _MEMORY_MAP_MODULE_H_
#define _MEMORY_MAP_MODULE_H_

#include "memory_map.h"
#include <algorithm>
#include <vector>
#include <memory>
#include <map>
using namespace std;

class MemoryMapSection;

class MemoryMapModule : public MemoryMap
{
public:
    using SectionMapType = std::map<std::string, std::shared_ptr<MemoryMapSection>>;

private:
    std::vector<std::shared_ptr<MemoryMap>> pages;
    ptrdiff_t base_addr;
    size_t    mod_size;
    std::string mod_name;
    SectionMapType sections;

public:
    MemoryMapModule() = delete;
    MemoryMapModule(const std::string& mod_name, std::vector<std::shared_ptr<MemoryMap>> sec_and_pages);

    virtual addr_t baseaddr() const override;
    virtual size_t size() const override;

    virtual char get_at(addr_t index) const override;
    virtual void set_at(addr_t index, char value) override;

    const std::string& module_name() const;
    const SectionMapType& get_sections() const;

    virtual void flush() override;
};

#endif // _MEMORY_MAP_MODULE_H_