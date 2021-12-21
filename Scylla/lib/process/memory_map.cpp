#include "process/memory_map.h"
#include "process/memory_map_iter.h"
using namespace std;


MemoryMapIter MemoryMap::begin() {
    return MemoryMapIter(this, 0);
}

MemoryMapIter MemoryMap::end() {
    return MemoryMapIter(this, this->size());
}
