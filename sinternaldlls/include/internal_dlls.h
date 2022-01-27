#ifndef _INTERNAL_DLLS_H_
#define _INTERNAL_DLLS_H_

#include <vector>
#include <string>


struct InternalDLLInfo {
    const unsigned char* m_data;
    size_t m_size;
    std::string m_dllname;
    std::string m_exchange_symbol;
};

extern const std::vector<InternalDLLInfo> internal_dlls;

#endif // _INTERNAL_DLLS_H_