#include "scylla/exchange_mx.h"
#include "utils.hpp"
#include <stdexcept>
#include <Windows.h>
using namespace std;


ExchangeDataMX::ExchangeDataMX(WinProcess_t process)
    : m_process(process)
    , m_udp_port(0)
    , m_udp_addr(0)
{
}

void ExchangeDataMX::set_udp_port(uint16_t port) {
    m_udp_port = port;
}

void ExchangeDataMX::set_udp_addr(uint32_t addr) {
    m_udp_addr = addr;
}

void ExchangeDataMX::add_entry(const std::string& dll, const std::string& func, void* hook, void* trampoline) {
    HookEntryMX entry;
    entry.dllname = dll;
    entry.funcname = func;
    entry.hook = hook;
    entry.trampoline = trampoline;
    m_entries.push_back(entry);
}

void ExchangeDataMX::remove_entry_by_trampoline(void* trmapoline) {
    for (auto it = m_entries.begin(); it != m_entries.end(); it++) {
        if (it->trampoline == trmapoline) {
            m_entries.erase(it);
            return;
        }
    }

    throw runtime_error("can't find trampoline");
}

void ExchangeDataMX::add_key_value(const std::string& key, const std::string& value) {
    if (m_key_value_str.find(key) != m_key_value_str.end())
        throw runtime_error("key already exists");
    m_key_value_str[key] = value;
}

void ExchangeDataMX::dump_to_process(void* addr) {
    ExchangeData data;
    DWORD mem_protect = PAGE_READONLY;
    data.m_udp_port = m_udp_port;
    data.m_udp_addr = m_udp_addr;
    data.m_entries = nullptr;
    data.m_numOfEntries = 0;
    data.m_key_value_str = nullptr;
    data.m_numOfKV = 0;
    bool return_success = false;

    auto allocate_entry = [&](const HookEntryMX& entry) {
        bool k_success = false;
        HookEntry ne;
        ne.hook = entry.hook;
        ne.trampoline = entry.trampoline;
        void* a1 = this->m_process->malloc(entry.dllname.size() + 1, 1, mem_protect);
        void* a2 = this->m_process->malloc(entry.funcname.size() + 1, 1, mem_protect);
        auto f1 = defer([&]() {if (a1 && !k_success) this->m_process->free(a1); });
        auto f2 = defer([&]() {if (a2 && !k_success) this->m_process->free(a2); });

        if (a1 == nullptr || a2 == nullptr)
            throw std::runtime_error("ExchangeDataMX::dump_to_process(): Failed to allocate memory");

        if (!this->m_process->write(a1, entry.dllname.c_str(), entry.dllname.size() + 1))
            throw std::runtime_error("ExchangeDataMX::dump_to_process(): Failed to write to memory");

        if (!this->m_process->write(a2, entry.funcname.c_str(), entry.funcname.size() + 1))
            throw std::runtime_error("ExchangeDataMX::dump_to_process(): Failed to write to memory");
        
        ne.dllname = (const char*)a1;
        ne.funcname = (const char*)a2;
        void* nx = this->m_process->malloc(sizeof(ne), 8, mem_protect);
        auto f3 = defer([&]() {if (nx && !k_success) this->m_process->free(nx); });

        if (nx == nullptr)
            throw std::runtime_error("ExchangeDataMX::dump_to_process(): Failed to allocate memory, align 8");
        
        if (!this->m_process->write(nx, &ne, sizeof(ne)))
            throw std::runtime_error("ExchangeDataMX::dump_to_process(): Failed to write to memory");

        k_success = true;
        return nx;
    };

    if (!this->m_entries.empty()) {
        bool scope_success = false;

        size_t ptrsize = this->m_process->is_64bit() ? 8 : 4;
        vector<void*> target_entries;
        auto f4 = defer([&]() {
            if (!scope_success) {
                for (auto& entry : target_entries) {
                    if (entry)
                        this->m_process->free(entry);
                }
            }
        });
        for (auto& entry : this->m_entries) {
            void* nx = allocate_entry(entry);
            target_entries.push_back(nx);
        }

        void* eaddr = this->m_process->malloc(ptrsize * this->m_entries.size(), 8, mem_protect);
        if (eaddr == nullptr)
            throw std::runtime_error("ExchangeDataMX::dump_to_process(): Failed to allocate memory for exchange data");
        auto f5 = defer([&]() { if (!scope_success) this->m_process->free(eaddr); });

        if (!this->m_process->write(eaddr, target_entries.data(), ptrsize * this->m_entries.size()))
            throw std::runtime_error("ExchangeDataMX::dump_to_process(): Failed to write to memory");

        data.m_entries = (HookEntry**)eaddr;
        data.m_numOfEntries = this->m_entries.size();

        scope_success = true;
    }

    auto allocate_kv = [&](const string& key, const string& val) {
        bool k_success = false;
        StringPair kv;
        void* a1 = this->m_process->malloc(key.size() + 1, 1, mem_protect);
        void* a2 = this->m_process->malloc(val.size() + 1, 1, mem_protect);
        void* a3 = this->m_process->malloc(sizeof(kv), 8, mem_protect);
        auto f1 = defer([&]() {if (a1 && !k_success) this->m_process->free(a1); });
        auto f2 = defer([&]() {if (a2 && !k_success) this->m_process->free(a2); });
        auto f3 = defer([&]() {if (a3 && !k_success) this->m_process->free(a3); });

        if (a1 == nullptr || a2 == nullptr || a3 == nullptr)
            throw std::runtime_error("ExchangeDataMX::dump_to_process(): Failed to allocate memory");
        
        if (!this->m_process->write(a1, key.c_str(), key.size() + 1))
            throw std::runtime_error("ExchangeDataMX::dump_to_process(): Failed to write to memory");
        
        if (!this->m_process->write(a2, val.c_str(), val.size() + 1))
            throw std::runtime_error("ExchangeDataMX::dump_to_process(): Failed to write to memory");
        
        kv.key   = (const char*)a1;
        kv.value = (const char*)a2;
        if (!this->m_process->write(a3, &kv, sizeof(kv)))
            throw std::runtime_error("ExchangeDataMX::dump_to_process(): Failed to write to memory");

        k_success = true;
        return a3;
    };
    if (!this->m_key_value_str.empty()) {
        bool scope_success = false;
        size_t ptrsize = this->m_process->is_64bit() ? 8 : 4;

        vector<void*> target_kv;
        for (auto& kv: this->m_key_value_str) {
            auto kva = allocate_kv(kv.first, kv.second);
            target_kv.push_back(kva);
        }

        void* kv_addr = this->m_process->malloc(ptrsize * this->m_key_value_str.size(), 8, mem_protect);
        if (kv_addr == nullptr)
            throw std::runtime_error("ExchangeDataMX::dump_to_process(): Failed to allocate memory for exchange data");
        auto f6 = defer([&]() { if (!scope_success) this->m_process->free(kv_addr); });

        if (!this->m_process->write(kv_addr, target_kv.data(), ptrsize * this->m_key_value_str.size()))
            throw std::runtime_error("ExchangeDataMX::dump_to_process(): Failed to write to memory");

        data.m_key_value_str = (StringPair**)kv_addr;
        data.m_numOfKV = this->m_key_value_str.size();

        scope_success = true;
    }

    if (!this->m_process->write(addr, &data, sizeof(data)))
        throw std::runtime_error("ExchangeDataMX::dump_to_process(): Failed to write to memory");

    return_success = true;
    return;
}
