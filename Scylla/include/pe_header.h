#ifndef _PE_HEADER_H_
#define _PE_HEADER_H_

#include <memory>
#include <vector>
#include <pe-parse/nt-headers.h>


class PEHeader {
private:
    std::shared_ptr<char> header_buffer;
    size_t header_size;
    void   parse_dos_header();
    size_t parse_nt_header_32();
    void   parse_section_headers(size_t offset);

public:
    peparse::dos_header dos;
    struct NtHeader{
        uint32_t nt_signature;
        peparse::file_header file_hdr;
        union OptionalHeader {
            peparse::optional_header_32 optional_hdr32;
            peparse::optional_header_64 optional_hdr64;
        } optional_hdr;
    } nthdr;
    std::vector<peparse::image_section_header> section_hdrs;

    PEHeader(std::shared_ptr<char> data, size_t size);
};

#endif // _PE_HEADER_H_