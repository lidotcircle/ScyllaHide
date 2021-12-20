#include "pe_header.h"
#include <stdexcept>
using namespace std;
using namespace peparse;

PEHeader::PEHeader(const vector<char>& data)
{
    this->_parse_header_throw(data);
}

void PEHeader::_parse_header_throw(const vector<char>& data)
{
    this->header_size = data.size();
    this->parse_dos_header(data);
    auto off = this->parse_nt_header_32(data);
    this->parse_section_headers(data, off);
}

bool PEHeader::parse_header(const vector<char>& data)
{
    try {
        this->_parse_header_throw(data);
        return true;
    } catch (const runtime_error&) {
        return false;
    }
}

void PEHeader::parse_dos_header(const vector<char>& data)
{
    if (this->header_size < sizeof(dos_header))
        throw runtime_error("dos header size is too small");

    this->dos = *reinterpret_cast<const dos_header*>(data.data());

    if (this->dos.e_magic != MZ_MAGIC)
        throw runtime_error("dos header magic is not correct");
}

size_t PEHeader::parse_nt_header_32(const vector<char>& data)
{
    auto offset = this->dos.e_lfanew;

    if (offset + sizeof(file_header) + sizeof(uint32_t) + sizeof(optional_header_32) > this->header_size)
        throw runtime_error("nt header offset is too large");

    this->nthdr.nt_signature = *reinterpret_cast<const uint32_t*>(data.data() + offset);
    if (this->nthdr.nt_signature != NT_MAGIC)
        throw runtime_error("nt header magic is not correct at offset " + to_string(offset));
    offset += sizeof(uint32_t);

    this->nthdr.file_hdr = *reinterpret_cast<const file_header*>(data.data() + offset);
    offset += sizeof(file_header);

    this->nthdr.optional_hdr.optional_hdr32.Magic = *reinterpret_cast<const uint16_t*>(data.data() + offset);
    if (this->nthdr.optional_hdr.optional_hdr32.Magic == NT_OPTIONAL_32_MAGIC) {
        this->nthdr.optional_hdr.optional_hdr32 = *reinterpret_cast<const optional_header_32*>(data.data() + offset);
        offset += sizeof(optional_header_32);
    } else {
        if (offset + sizeof(optional_header_64) > this->header_size)
            throw runtime_error("nt header offset is too large");

        this->nthdr.optional_hdr.optional_hdr64 = *reinterpret_cast<const optional_header_64*>(data.data() + offset);
        offset += sizeof(optional_header_64);
    }

    return offset;
}

uint32_t PEHeader::entrypointRVA() const {
    if (this->is_64bit()) {
        return this->nthdr.optional_hdr.optional_hdr64.AddressOfEntryPoint;
    } else {
        return this->nthdr.optional_hdr.optional_hdr32.AddressOfEntryPoint;
    }
}

uint64_t PEHeader::imageBase() const {
    if (this->is_64bit())
        return this->nthdr.optional_hdr.optional_hdr64.ImageBase;
    else
        return this->nthdr.optional_hdr.optional_hdr32.ImageBase;
}

bool PEHeader::is_64bit() const {
    return this->nthdr.optional_hdr.optional_hdr32.Magic != NT_OPTIONAL_32_MAGIC;
}

uint16_t PEHeader::machine() const {
    return this->nthdr.file_hdr.Machine;
}

uint16_t PEHeader::characteristics() const {
    return this->nthdr.file_hdr.Characteristics;
}

bool PEHeader::relocatable() const {
    return (this->characteristics() & IMAGE_FILE_RELOCS_STRIPPED) == 0;
}

bool PEHeader::is_exe() const {
    return (this->characteristics() & IMAGE_FILE_DLL) == 0;
}

const data_directory* PEHeader::__data_directory() const {
    if (this->is_64bit())
        return this->nthdr.optional_hdr.optional_hdr64.DataDirectory;
    else
        return this->nthdr.optional_hdr.optional_hdr32.DataDirectory;
}
vector<data_directory> PEHeader::data_directories() const {
    auto dr = this->__data_directory();
    return vector<data_directory>(dr, dr + DIR_RESERVED);
}

size_t PEHeader::sizeOfHeaders() const {
    if (this->is_64bit())
        return this->nthdr.optional_hdr.optional_hdr64.SizeOfHeaders;
    else
        return this->nthdr.optional_hdr.optional_hdr32.SizeOfHeaders;
}
size_t PEHeader::sizeOfImage() const {
    if (this->is_64bit())
        return this->nthdr.optional_hdr.optional_hdr64.SizeOfImage;
    else
        return this->nthdr.optional_hdr.optional_hdr32.SizeOfImage;
}
size_t PEHeader::sizeofCode() const {
    if (this->is_64bit())
        return this->nthdr.optional_hdr.optional_hdr64.SizeOfCode;
    else
        return this->nthdr.optional_hdr.optional_hdr32.SizeOfCode;
}
size_t PEHeader::sizeOfInitializedData() const {
    if (this->is_64bit())
        return this->nthdr.optional_hdr.optional_hdr64.SizeOfInitializedData;
    else
        return this->nthdr.optional_hdr.optional_hdr32.SizeOfInitializedData;
}
size_t PEHeader::sizeOfUninitializedData() const {
    if (this->is_64bit())
        return this->nthdr.optional_hdr.optional_hdr64.SizeOfUninitializedData;
    else
        return this->nthdr.optional_hdr.optional_hdr32.SizeOfUninitializedData;
}

data_directory PEHeader::directory_export() const { return this->__data_directory()[DIR_EXPORT]; }
data_directory PEHeader::directory_import() const { return this->__data_directory()[DIR_IMPORT]; }
data_directory PEHeader::directory_resource() const { return this->__data_directory()[DIR_RESOURCE]; }
data_directory PEHeader::directory_exception() const { return this->__data_directory()[DIR_EXCEPTION]; }
data_directory PEHeader::directory_security() const { return this->__data_directory()[DIR_SECURITY]; }
data_directory PEHeader::directory_basereloc() const { return this->__data_directory()[DIR_BASERELOC]; }
data_directory PEHeader::directory_debug() const { return this->__data_directory()[DIR_DEBUG]; }
data_directory PEHeader::directory_architecture() const { return this->__data_directory()[DIR_ARCHITECTURE]; }
data_directory PEHeader::directory_globalptr() const { return this->__data_directory()[DIR_GLOBALPTR]; }
data_directory PEHeader::directory_tls() const { return this->__data_directory()[DIR_TLS]; }
data_directory PEHeader::directory_load_config() const { return this->__data_directory()[DIR_LOAD_CONFIG]; }
data_directory PEHeader::directory_bound_import() const { return this->__data_directory()[DIR_BOUND_IMPORT]; }
data_directory PEHeader::directory_iat() const { return this->__data_directory()[DIR_IAT]; }
data_directory PEHeader::directory_delay_import() const { return this->__data_directory()[DIR_DELAY_IMPORT]; }
data_directory PEHeader::directory_com_descriptor() const { return this->__data_directory()[DIR_COM_DESCRIPTOR]; }

void PEHeader::parse_section_headers(const vector<char>& data, size_t offset)
{
    auto base = data.data() + offset;

    for (size_t i=0;i<this->nthdr.file_hdr.NumberOfSections;i++) {
        if (offset + (i + 1) * sizeof(image_section_header) > this->header_size)
            throw runtime_error("section header offset is too large");
        auto section = *reinterpret_cast<const image_section_header*>(base + i * sizeof(image_section_header));
        this->section_hdrs.push_back(section);
    }
}