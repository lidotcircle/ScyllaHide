#include "process/memory_map_raw.h"
#include <vector>
#include <stdexcept>
using namespace std;

using addr_t = typename MemoryMapRaw::addr_t;


MemoryMapRaw::MemoryMapRaw(addr_t base, size_t size): base_addr(base), data(size) { }

char MemoryMapRaw::get_at(addr_t index) const {
    if (index < 0 || index >= data.size())
        throw out_of_range("index out of range");
    return data[index];
}
void MemoryMapRaw::set_at(addr_t index, char value) {
    if (index < 0 || index >= data.size())
        throw out_of_range("index out of range");
    data[index] = value;
}

addr_t MemoryMapRaw::baseaddr() const {
    return base_addr;
}
size_t MemoryMapRaw::size() const {
    return data.size();
}
