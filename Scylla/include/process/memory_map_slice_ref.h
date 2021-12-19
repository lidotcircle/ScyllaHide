#ifndef _MEMORY_MAP_SLICE_REF_H_
#define _MEMORY_MAP_SLICE_REF_H_

#include "memory_map.h"

class MemoryMapSliceRef : public MemoryMap
{
public:
    using addr_t = typename MemoryMap::addr_t;

private:
    MemoryMap& m_map;
    addr_t m_offset;
    size_t m_size;

public:
    MemoryMapSliceRef(MemoryMap& map, addr_t offset, size_t size);
    virtual addr_t baseaddr() const override;
    virtual size_t size() const override;
    virtual char get_at(addr_t index) const override;
    virtual void set_at(addr_t index, char value) override;
    virtual void flush() override;
};

#endif // _MEMORY_MAP_SLICE_REF_H_