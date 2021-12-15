#ifndef _MEMORY_MAP_SECTION_H_
#define _MEMORY_MAP_SECTION_H_

#include "memory_map.h"
#include <vector>
#include <memory>
using namespace std;

class MemoryMapSection : public MemoryMap
{
private:
    std::vector<std::shared_ptr<MemoryMap>> pages;
    ptrdiff_t base_addr;
    size_t    sec_size;
    std::string sec_name;

public:
    MemoryMapSection() = delete;
    MemoryMapSection(const std::string& sec_name, std::vector<std::shared_ptr<MemoryMap>> pages);

    virtual addr_t baseaddr() const override;
    virtual size_t size() const override;

    virtual char get_at(addr_t index) const override;
    virtual void set_at(addr_t index, char value) override;

    const std::string& section_name() const;

    virtual void flush() override;
};

#endif // _MEMORY_MAP_SECTION_H_