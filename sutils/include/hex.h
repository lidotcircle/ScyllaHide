#ifndef _SUTILS_HEX_H_
#define _SUTILS_HEX_H_

#include <vector>
#include <string>


std::string hex_encode(const void* src, size_t src_len, const std::string& delim = "", size_t len_per_line = 0);
std::vector<char> hex_decode(const std::string& base64_str);

#endif // _SUTILS_HEX_H_