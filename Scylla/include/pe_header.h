#ifndef _PE_HEADER_H_
#define _PE_HEADER_H_

#include <vector>
#include <pe-parse/nt-headers.h>


class PEHeader {
private:
    size_t header_size;
    void   parse_dos_header(const std::vector<char>& data);
    size_t parse_nt_header_32(const std::vector<char>& data);
    void   parse_section_headers(const std::vector<char>& data, size_t offset);
    const peparse::data_directory* __data_directory() const;

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

    uint32_t entrypointRVA() const;
    uint64_t imageBase() const;
    bool is_64bit() const;
    uint16_t characteristics() const;
    uint16_t machine() const;
    bool relocatable() const;
    bool is_exe() const;
    std::vector<peparse::data_directory> data_directories() const;

    size_t sizeOfHeaders() const;
    size_t sizeOfImage() const;
    size_t sizeofCode() const;
    size_t sizeOfInitializedData() const;
    size_t sizeOfUninitializedData() const;

    peparse::data_directory directory_export() const;
    peparse::data_directory directory_import() const;
    peparse::data_directory directory_resource() const;
    peparse::data_directory directory_exception() const;
    peparse::data_directory directory_security() const;
    peparse::data_directory directory_basereloc() const;
    peparse::data_directory directory_debug() const;
    peparse::data_directory directory_architecture() const;
    peparse::data_directory directory_globalptr() const;
    peparse::data_directory directory_tls() const;
    peparse::data_directory directory_load_config() const;
    peparse::data_directory directory_bound_import() const;
    peparse::data_directory directory_iat() const;
    peparse::data_directory directory_delay_import() const;
    peparse::data_directory directory_com_descriptor() const;

    PEHeader() = default;
    PEHeader(const std::vector<char>& data);

    bool parse_header(const std::vector<char>& data);
};

#endif // _PE_HEADER_H_