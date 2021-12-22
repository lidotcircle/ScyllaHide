#include "str_utils.h"
#include <string>
#include <cstdio>
#include <stdarg.h>
using namespace std;


string integer2str(size_t val, uint8_t base) {
    char buf[32];
    _itoa_s(val, buf, base);
    return string(buf);
}

std::string strformat(const char* fmt, ...) {
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    return string(buf);
}