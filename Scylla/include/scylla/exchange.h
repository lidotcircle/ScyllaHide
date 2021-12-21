#ifndef _SCYLLA_EXCHANGE_H_
#define _SCYLLA_EXCHANGE_H_

#include <stdint.h>


struct HookEntry {
    const char* dllname;
    const char* funcname;
    void* hook;
    void* trampoline;
};

struct ExchangeData {
    uint16_t   m_udp_port;
    uint32_t   m_udp_addr;
    HookEntry* m_entries;
    uint32_t   m_numOfEntries;

    void* lookup_trampoline(void* hook);
    void* lookup_trampoline(const char* funcname);
    void* lookup_trampoline(const char* dllname, const char* funcname);
};

#endif // _SCYLLA_EXCHANGE_H_