#ifndef _SUTILS_BASE64_H_
#define _SUTILS_BASE64_H_

#include <vector>
#include <string>


std::string base64_encode(const void* src, size_t src_len);
std::vector<char> base64_decode(const std::string& base64_str);

#endif // _SUTILS_BASE64_H_