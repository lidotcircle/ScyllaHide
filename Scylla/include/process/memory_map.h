#ifndef _MEMORY_MAP_H_
#define _MEMORY_MAP_H_

#include <vector>
#include <string>
#include "memory_map_iter.h"
#include "mem_indexable.h"


class MemoryMap: public MemIndexable {
public:
    virtual addr_t baseaddr() const = 0;
    virtual size_t size() const = 0;

    virtual ~MemoryMap() = default;

    MemoryMapIter begin();
    MemoryMapIter end();
};

#endif // _MEMORY_MAP_H_
