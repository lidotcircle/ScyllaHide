#ifndef _STR_UTILS_H
#define _STR_UTILS_H

#include <string>

std::string integer2str(size_t val, uint8_t base = 10);
std::string strformat  (const char* fmt, ...);
std::string canonicalizeModuleName(std::string name);

#endif // _STR_UTILS_H