#include "process/memory_map_pefile.h"
#include "process/pe_header.h"
#include <pe-parse/parse.h>
#include <stdexcept>
#include <fstream>
using namespace std;

#define MAX_AB(a, b) ((a) > (b) ? (a) : (b))


MemoryMapPEFile::MemoryMapPEFile(const vector<char>& buf) {
    this->parse_data(buf);
}

MemoryMapPEFile::MemoryMapPEFile(const string& filename) {
    ifstream file(filename, ios::binary | ios::ate);

    if (!file.is_open())
        throw runtime_error("Failed to open file");

    size_t size = file.tellg();
    file.seekg(0, ios::beg);
    vector<char> buf(size);
    file.read(buf.data(), size);

    this->parse_data(buf);
}

void MemoryMapPEFile::parse_data(const vector<char>& buf) {
    PEHeader header(buf);

    if (header.sizeOfImage() < buf.size())
        throw runtime_error("invalid pe file, sizeOfImage is too small");

    vector<char> image_data(header.sizeOfImage(), 0);
    this->base_address = (addr_t)header.imageBase();

    if (header.sizeOfHeaders() > buf.size())
        throw runtime_error("invalid pe file, sizeOfHeaders is too large");
    std::copy(buf.begin(), buf.begin() + header.sizeOfHeaders(), image_data.begin());

    for(auto& sec: header.section_hdrs) {
        if (sec.VirtualAddress + sec.SizeOfRawData > image_data.size())
            throw runtime_error("invalid pe file, section VirtualAddress is too large");
        
        std::copy(buf.begin() + sec.PointerToRawData, 
                 buf.begin() + sec.PointerToRawData + sec.SizeOfRawData,
                 image_data.begin() + sec.VirtualAddress);
    }

    this->data = std::move(image_data);
    this->parse_header(header);
}

void MemoryMapPEFile::change_base(addr_t new_base) {
    this->base_address = new_base;
}

char MemoryMapPEFile::get_at(addr_t offset) const {
    if (offset >= this->data.size()) {
        throw runtime_error("offset out of bounds");
    }

    return this->data[offset];
}

void MemoryMapPEFile::set_at(addr_t offset, char value) {
    if (offset >= this->data.size()) {
        throw runtime_error("offset out of bounds");
    }

    this->data[offset] = value;
}

MemoryMapPEFile::addr_t MemoryMapPEFile::baseaddr() const {
    return this->base_address;
}

size_t MemoryMapPEFile::size() const {
    return this->data.size();
}

const char* MemoryMapPEFile::data_ptr() const {
    return this->data.data();
}

MemoryMapPEFile::~MemoryMapPEFile() {
}
