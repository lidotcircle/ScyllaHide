#include "pe_header.h"
#include <stdexcept>
using namespace std;
using namespace peparse;

PEHeader::PEHeader(shared_ptr<char> buffer, size_t size)
    : header_buffer(buffer), header_size(size)
{
    this->parse_dos_header();
    auto off = this->parse_nt_header_32();
    this->parse_section_headers(off);
}

void PEHeader::parse_dos_header()
{
    if (this->header_size < sizeof(dos_header))
        throw runtime_error("dos header size is too small");

    this->dos = *reinterpret_cast<dos_header*>(this->header_buffer.get());

    if (this->dos.e_magic != MZ_MAGIC)
        throw runtime_error("dos header magic is not correct");
}

size_t PEHeader::parse_nt_header_32()
{
    auto offset = this->dos.e_lfanew;

    if (offset + sizeof(file_header) + sizeof(uint32_t) + sizeof(optional_header_32) > this->header_size)
        throw runtime_error("nt header offset is too large");

    this->nthdr.nt_signature = *reinterpret_cast<uint32_t*>(this->header_buffer.get() + offset);
    if (this->nthdr.nt_signature != NT_MAGIC)
        throw runtime_error("nt header magic is not correct");
    offset += sizeof(uint32_t);

    this->nthdr.file_hdr = *reinterpret_cast<file_header*>(this->header_buffer.get() + offset);
    offset += sizeof(file_header);

    this->nthdr.optional_hdr.optional_hdr32.Magic = *reinterpret_cast<uint16_t*>(this->header_buffer.get() + offset);
    if (this->nthdr.optional_hdr.optional_hdr32.Magic == NT_OPTIONAL_32_MAGIC) {
        this->nthdr.optional_hdr.optional_hdr32 = *reinterpret_cast<optional_header_32*>(this->header_buffer.get() + offset);
        offset += sizeof(optional_header_32);
    } else {
        if (offset + sizeof(optional_header_64) > this->header_size)
            throw runtime_error("nt header offset is too large");

        this->nthdr.optional_hdr.optional_hdr64 = *reinterpret_cast<optional_header_64*>(this->header_buffer.get() + offset);
        offset += sizeof(optional_header_64);
    }

    return offset;
}

void PEHeader::parse_section_headers(size_t offset)
{
    auto base = this->header_buffer.get() + offset;

    for (size_t i=0;i<this->nthdr.file_hdr.NumberOfSections;i++) {
        if (offset + (i + 1) * sizeof(image_section_header) > this->header_size)
            throw runtime_error("section header offset is too large");
        auto section = *reinterpret_cast<image_section_header*>(base + i * sizeof(image_section_header));
        this->section_hdrs.push_back(section);
    }
}