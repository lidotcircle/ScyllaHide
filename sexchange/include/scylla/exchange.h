#ifndef _SCYLLA_EXCHANGE_H_
#define _SCYLLA_EXCHANGE_H_

#include <stdint.h>


struct HookEntry {
    const char* dllname;
    const char* funcname;
    void* hook;
    void* trampoline;
};

struct StringPair {
    const char* key;
    const char* value;
};

struct ExchangeData {
    uint16_t     m_udp_port;
    uint32_t     m_udp_addr;
    HookEntry**  m_entries;
    uint32_t     m_numOfEntries;
    StringPair** m_key_value_str;
    uint32_t     m_numOfKV;

    void* lookup_trampoline(void* hook);
    void* lookup_trampoline(const char* funcname);
    void* lookup_trampoline(const char* dllname, const char* funcname);

    template<typename T>
    T lookup_trampoline(void* hook) {
        return static_cast<T>(lookup_trampoline(hook));
    }

    template<typename T>
    T lookup_trampoline(const char* funcname) {
        return static_cast<T>(lookup_trampoline(funcname));
    }

    template<typename T>
    T lookup_trampoline(const char* dllname, const char* funcname) {
        return static_cast<T>(lookup_trampoline(dllname, funcname));
    }

    const char* lookup_key(const char* key);
};

#endif // _SCYLLA_EXCHANGE_H_