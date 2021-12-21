#include "process/memory_map_collection.h"
#include <stdexcept>
#include <sstream>
#include <iomanip>
using namespace std;

template<typename T>
static string to_hex_string(T addr)
{
    stringstream ss;
    ss << hex << addr;
    return ss.str();
}

char MemoryMapCollection::get_at(addr_t addr) const {
    for (size_t i=0;i<this->map_count();i++) {
        auto region = this->get_map(i);
        auto base = region->baseaddr();
        if (base <= addr && addr < base + region->size()) {
            return region->get_at(addr - base);
        }
    }

    throw runtime_error("MemoryMapCollection::get_at() Address not mapped: " + to_hex_string(addr));
}

const std::shared_ptr<MemoryMap> MemoryMapCollection::get_map(addr_t index) const {
    auto _this = const_cast<MemoryMapCollection*>(this);
    return _this->get_map(index);
}

void MemoryMapCollection::set_at(addr_t addr, char value) {
    for (size_t i=0;i<this->map_count();i++) {
        auto region = this->get_map(i);
        auto base = region->baseaddr();
        if (base <= addr && addr < base + region->size()) {
            return region->set_at(addr - base, value);
        }
    }

    throw runtime_error("MemoryMapCollection::set_at() Address not mapped: " + to_hex_string(addr));
}

bool MemoryMapCollection::is_valid_addr(addr_t addr) {
    for (size_t i=0;i<this->map_count();i++) {
        auto region = this->get_map(i);
        auto base = region->baseaddr();
        if (base <= addr && addr < base + region->size()) {
            return true;
        }
    }

    return false;
}

MemoryValueRef MemoryMapCollection::operator[] (addr_t addr) {
    if (!this->is_valid_addr(addr))
        throw runtime_error("MemoryMapCollection::operator[] Address not mapped: " + to_hex_string(addr));

    return MemoryValueRef(this, addr);
}

void MemoryMapCollection::flush() {
    for (size_t i=0;i<this->map_count();i++) {
        auto region = this->get_map(i);
        region->flush();
    }
}