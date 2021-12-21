#include "scylla/exchange.h"

static char char_tolower(char c) {
    if (c >= 'A' && c <= 'Z') {
        return c + ('a' - 'A');
    }

    return c;
}
static int strcmp_nocase(const char* a, const char* b) {
    for (;*a && *b; ++a, ++b) {
        char c1 = char_tolower(*a);
        char c2 = char_tolower(*b);

        if (c1 > c2) {
            return 1;
        } else if (c1 < c2) {
            return -1;
        }
    }

    if (*a) return  1;
    if (*b) return -1;
    return 0;
}

void* ExchangeData::lookup_trampoline(void* hook) {
    for(size_t i=0;i<m_numOfEntries;i++) {
        if(m_entries[i]->hook == hook) {
            return m_entries[i]->trampoline;
        }
    }

    return nullptr;
}

void* ExchangeData::lookup_trampoline(const char* funcname) {
    for(size_t i=0;i<m_numOfEntries;i++) {
        if(strcmp_nocase(m_entries[i]->funcname, funcname) == 0) {
            return m_entries[i]->trampoline;
        }
    }

    return nullptr;
}

void* ExchangeData::lookup_trampoline(const char* dllname, const char* funcname) {
    for(size_t i=0;i<m_numOfEntries;i++) {
        if(strcmp_nocase(m_entries[i]->dllname, dllname) == 0 &&
           strcmp_nocase(m_entries[i]->funcname, funcname) == 0)
        {
            return m_entries[i]->trampoline;
        }
    }

    return nullptr;
}

const char* ExchangeData::lookup_key(const char* key) {
    for(size_t i=0;i<m_numOfKV;i++) {
        if(strcmp_nocase(m_key_value_str[i]->key, key) == 0) {
            return m_key_value_str[i]->value;
        }
    }

    return nullptr;
}