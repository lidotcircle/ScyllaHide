#ifndef _MAP_PE_MODULE_H_
#define _MAP_PE_MODULE_H_

#include "./pe_header.h"
#include "memory_map.h"
#include <vector>
#include <string>
#include <memory>
#include <map>

union ImportEntry {
private:
    struct {
        bool is_ordinal;
        uint16_t ordinal;
    } m_ordinal;

    struct {
        bool is_ordinal;
        std::string* name;
    } m_name;

public:
    ImportEntry() = delete;
    ImportEntry(const ImportEntry&);
    ImportEntry(ImportEntry&&);
    ImportEntry(uint16_t ordinal);
    ImportEntry(const std::string& name);

    ImportEntry& operator=(const ImportEntry&);
    ImportEntry& operator=(ImportEntry&&);

    bool operator< (const ImportEntry& other) const;
    bool operator==(const ImportEntry& other) const;
    bool operator!=(const ImportEntry& other) const;

    std::string symbolname() const;
    uint16_t ordinal() const;

    bool is_ordinal() const;

    ~ImportEntry();
};

class MapPEModule : public virtual MemoryMap
{
public:
    using addr_t = typename MemoryMap::addr_t;

private:
    std::string mod_name;
    PEHeader m_header;
    std::shared_ptr<std::map<uint32_t,std::pair<std::string,addr_t>>> m_exports;
    std::shared_ptr<std::map<std::string,std::map<ImportEntry,addr_t>>> m_imports;
    bool m_parsed;

protected:
    void parse_header(PEHeader header);
    virtual void change_base(addr_t new_base);

public:
    MapPEModule();
    MapPEModule(const std::string& mod_name);

    std::vector<std::string> sections() const;
    std::shared_ptr<MemoryMap>       section(const std::string& name);
    const std::shared_ptr<MemoryMap> section(const std::string& name) const;
    const std::string& module_name()  const;

    const PEHeader& header() const;

    const std::map<uint32_t,std::pair<std::string,addr_t>>&   exports() const;
    addr_t resolve_export(const std::string& name) const;
    addr_t resolve_export(uint32_t ordinal) const;
    const std::map<std::string,std::map<ImportEntry,addr_t>>& imports() const;

    bool relocatable() const;
    void base_relocate(addr_t base);
};

#endif // _MAP_PE_MODULE_H_