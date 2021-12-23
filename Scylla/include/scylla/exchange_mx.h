#ifndef _SCYLLA_EXCHANGE_MX_H_
#define _SCYLLA_EXCHANGE_MX_H_

#include "./exchange.h"
#include "../process/win_process_native.h"
#include <vector>
#include <string>
#include <map>

class ExchangeDataMX {
private:
    struct HookEntryMX {
        std::string dllname;
        std::string funcname;
        void* hook;
        void* trampoline;
    };

    WinProcess_t m_process;
    std::vector<HookEntryMX> m_entries;
    std::map<std::string,std::string> m_key_value_str;
    uint16_t m_udp_port;
    uint32_t m_udp_addr;

public:
    ExchangeDataMX(WinProcess_t process);

    void set_udp_port(uint16_t port);
    void set_udp_addr(uint32_t addr);

    void add_entry(const std::string& dll, const std::string& func, void* hook, void* trampoline);
    void remove_entry_by_trampoline(void* trampoline);
    void add_key_value(const std::string& key, const std::string& value);

    void dump_to_process(void* addr);
};

#endif // _SCYLLA_EXCHANGE_MX_H_