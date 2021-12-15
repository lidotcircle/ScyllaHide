#include "process/memory_map_pefile.h"
#include <pe-parse/parse.h>
#include <stdexcept>
using namespace std;


MemoryMapPEFile::MemoryMapPEFile(const peparse::bounded_buffer* buffr, void* base_addr, size_t size, const std::string& secname):
    buffer(buffr), base_address(reinterpret_cast<addr_t>(base_addr)), map_size(size), m_section_name(secname)
{
}

char MemoryMapPEFile::get_at(addr_t offset) const {
    if (offset >= map_size) {
        throw runtime_error("offset out of bounds");
    }

    uint8_t value;
    peparse::readByte(const_cast<peparse::bounded_buffer*>(this->buffer), offset, value);

    return value;
}

void MemoryMapPEFile::set_at(addr_t offset, char value) {
    throw std::runtime_error("pe file is read only");
}

MemoryMapPEFile::addr_t MemoryMapPEFile::baseaddr() const {
    return this->base_address;
}

size_t MemoryMapPEFile::size() const {
    return this->map_size;
}

bool MemoryMapPEFile::is_section() const {
    return !this->m_section_name.empty();
}

const string& MemoryMapPEFile::section_name() const {
    return this->m_section_name;
}

MemoryMapPEFile::~MemoryMapPEFile() {
}
