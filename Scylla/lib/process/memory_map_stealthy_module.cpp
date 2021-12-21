#include "process/memory_map_stealthy_module.h"
#include <string>
#include <memory>
using namespace std;

using addr_t = typename MemoryMapStealthyModule::addr_t;

#define MIN_AB(a, b) ((a) < (b) ? (a) : (b))


MemoryMapStealthyModule::MemoryMapStealthyModule(
    shared_ptr<MemoryMapWinPage> page,
    const string& modname): page(page), dll_path(modname) 
{
    vector <char> data(MIN_AB(page->size(), 0x1000), 0);
    for (size_t i = 0; i < page->size(); i++)
        data[i] = page->get_at(i);

    PEHeader header(data);
    this->parse_header(header);
}

MemoryMapStealthyModule::MemoryMapStealthyModule(
    shared_ptr<MemoryMapWinPage> page,
    PEHeader header, const string& modname): page(page), dll_path(modname) 
{
    this->parse_header(header);
}

addr_t MemoryMapStealthyModule::baseaddr() const {
    return page->baseaddr();
}
size_t MemoryMapStealthyModule::size() const {
    return page->size();
}

char MemoryMapStealthyModule::get_at(addr_t index) const {
    return page->get_at(index);
}
void MemoryMapStealthyModule::set_at(addr_t index, char value) {
    page->set_at(index, value);
}

void MemoryMapStealthyModule::flush() {
    page->flush();
}

const std::string& MemoryMapStealthyModule::module_name() const {
    return dll_path;
}
