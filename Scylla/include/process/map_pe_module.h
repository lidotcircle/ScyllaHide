#ifndef _MAP_PE_MODULE_H_
#define _MAP_PE_MODULE_H_

#include "memory_map.h"
#include "pe_header.h"
#include <vector>
#include <string>
#include <memory>
#include <map>


class MapPEModule : public virtual MemoryMap
{
public:
    using addr_t = typename MemoryMap::addr_t;

private:
    std::string mod_name;
    PEHeader m_header;
    std::shared_ptr<std::map<std::string,addr_t>> m_exports;
    std::shared_ptr<std::map<std::string,std::map<std::string,addr_t>>> m_imports;
    bool m_parsed;

protected:
    void parse_header(PEHeader header);

public:
    MapPEModule();
    MapPEModule(const std::string& mod_name);

    std::vector<std::string> sections() const;
    std::shared_ptr<MemoryMap>       section(const std::string& name);
    const std::shared_ptr<MemoryMap> section(const std::string& name) const;
    const std::string& module_name()  const;

    const PEHeader& header() const;
    const std::map<std::string,addr_t>&                       exports() const;
    const std::map<std::string,std::map<std::string,addr_t>>& imports() const;
};



#endif // _MAP_PE_MODULE_H_