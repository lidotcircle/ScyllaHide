#include "process/memory_map_stealthy_module.h"
#include <string>
#include <memory>
using namespace std;

using addr_t = typename MemoryMapStealthyModule::addr_t;


MemoryMapStealthyModule::MemoryMapStealthyModule(
    shared_ptr<MemoryMapWinPage> page,
    const string& modname): page(page), dll_path(modname) {}

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
