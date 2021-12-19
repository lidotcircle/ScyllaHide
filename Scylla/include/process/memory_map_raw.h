#ifndef _MEMORY_MAP_RAW_H_
#define _MEMORY_MAP_RAW_H_

#include "memory_map.h"
#include <vector>


class MemoryMapRaw : public MemoryMap
{
public:
    using addr_t = typename MemoryMap::addr_t;

private:
    std::vector<char> data;
    addr_t base_addr;

public:
    MemoryMapRaw(addr_t base, size_t size);

    virtual char get_at(addr_t index) const override;
    virtual void set_at(addr_t index, char value) override;

    virtual addr_t baseaddr() const override;
    virtual size_t size() const override;

    ~MemoryMapRaw() = default;
};

#endif // _MEMORY_MAP_RAW_H_