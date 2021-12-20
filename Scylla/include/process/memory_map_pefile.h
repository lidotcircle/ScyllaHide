#ifndef _MEMORY_MAP_PEFILE_H_
#define _MEMORY_MAP_PEFILE_H_

#include "map_pe_module.h"
#include <string>
#include <vector>


class MemoryMapPEFile : public MapPEModule
{
private:
    addr_t base_address;
    std::vector<char> data;
    virtual void change_base(addr_t new_base) override;
    void parse_data(const std::vector<char>& buf);

public:
    MemoryMapPEFile(const std::vector<char>& buf);
    MemoryMapPEFile(const std::string& file_name);

    virtual char get_at(addr_t offset) const override;
    virtual void set_at(addr_t offset, char value) override;

    virtual addr_t baseaddr() const override;
    virtual size_t size() const override;

    ~MemoryMapPEFile();
};

#endif // _MEMORY_MAP_PEFILE_H_