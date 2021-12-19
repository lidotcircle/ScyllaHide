#ifndef _MEMORY_MAP_MODULE_H_
#define _MEMORY_MAP_MODULE_H_

#include "map_pe_module.h"
#include "pe_header.h"
#include <algorithm>
#include <vector>
#include <memory>
#include <map>


class MemoryMapSection;

class MemoryMapModule : public MapPEModule
{
public:
    using SectionMapType = std::map<std::string, std::shared_ptr<MemoryMapSection>>;
    using addr_t = typename MemoryMap::addr_t;

private:
    std::vector<std::shared_ptr<MemoryMap>> pages;
    ptrdiff_t base_addr;
    size_t    mod_size;
    SectionMapType sections;

public:
    MemoryMapModule() = delete;
    MemoryMapModule(const std::string& mod_name, PEHeader header, std::vector<std::shared_ptr<MemoryMap>> sec_and_pages);

    virtual addr_t baseaddr() const override;
    virtual size_t size() const override;

    virtual char get_at(addr_t index) const override;
    virtual void set_at(addr_t index, char value) override;

    virtual void flush() override;

    const SectionMapType& get_sections() const;
    SectionMapType&       get_sections();
};

#endif // _MEMORY_MAP_MODULE_H_