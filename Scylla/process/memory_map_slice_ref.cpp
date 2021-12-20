#include "process/memory_map_slice_ref.h"
#include <stdexcept>
using namespace std;


MemoryMapSliceRef::MemoryMapSliceRef(MemoryMap& map, addr_t offset, size_t size)
    : m_map(map) , m_offset(offset), m_size(size)
{
}

MemoryMapSliceRef::addr_t MemoryMapSliceRef::baseaddr() const
{
    return m_offset + m_map.baseaddr();
}

size_t MemoryMapSliceRef::size() const
{
    return m_size;
}

char MemoryMapSliceRef::get_at(addr_t index) const
{
    if (index >= m_size)
        throw runtime_error("index out of range");
    return m_map.get_at(index + m_offset);
}

void MemoryMapSliceRef::set_at(addr_t index, char value)
{
    if (index >= m_size)
        throw runtime_error("index out of range");
    m_map.set_at(index + m_offset, value);
}

void MemoryMapSliceRef::flush()
{
    m_map.flush();
}