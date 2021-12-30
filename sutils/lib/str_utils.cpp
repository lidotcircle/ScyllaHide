#include "str_utils.h"
#include <string>
#include <cstdio>
#include <stdarg.h>
#include <algorithm>
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

string trimstring(string str) {
    if (str.find_first_not_of(" \t\r\n") != string::npos)
        str.erase(0, str.find_first_not_of(" \t\r\n"));

    if (str.find_last_not_of(" \t\r\n") != string::npos)
        str.erase(str.find_last_not_of(" \t\r\n") + 1);

    return str;
}

string canonicalizeModuleName(string name) {
    std::transform(name.begin(), name.end(), name.begin(), ::tolower);
    if (name.find_last_of('\\') != string::npos)
        name = name.substr(name.find_last_of('\\') + 1);

    if (name.find_last_of('/') != string::npos)
        name = name.substr(name.find_last_of('/') + 1);

    return name;
}