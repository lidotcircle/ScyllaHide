#include "process/memory_map_module.h"
#include "process/memory_map_section.h"
#include <algorithm>
#include <stdexcept>
using namespace std;


MemoryMapModule::MemoryMapModule(const std::string& mod_name, std::vector<std::shared_ptr<MemoryMap>> _pages):
    mod_name(mod_name), pages(std::move(_pages))
{
    if (this->pages.empty())
        throw std::runtime_error("MemoryMapModule: no pages");

    std::sort(this->pages.begin(), this->pages.end(), [](const std::shared_ptr<MemoryMap>& a, const std::shared_ptr<MemoryMap>& b) {
        return a->baseaddr() < b->baseaddr();
    });

    for (auto& sec: this->pages) {
        auto secm = std::dynamic_pointer_cast<MemoryMapSection>(sec);
        if (secm) {
            this->sections[secm->section_name()] = secm;
        }
    }

    this->base_addr = this->pages.front()->baseaddr();
    this->mod_size = this->pages.back()->baseaddr() + this->pages.back()->size() - this->base_addr;
}

MemoryMapModule::addr_t MemoryMapModule::baseaddr() const {
    return this->base_addr;
}

size_t MemoryMapModule::size() const {
    return this->mod_size;
}

char MemoryMapModule::get_at(addr_t index) const {
    index += this->base_addr;
    auto page = std::lower_bound(this->pages.begin(), this->pages.end(), index, [](const std::shared_ptr<MemoryMap>& page, addr_t index) {
        return page->baseaddr() + page->size() <= index;
    });

    if (page == this->pages.end()) {
        throw std::runtime_error("MemoryMapModule: index out of range or there is a hole");
    }

    return (*page)->get_at(index - (*page)->baseaddr());
}

void MemoryMapModule::set_at(addr_t index, char value) {
    index += this->base_addr;
    auto page = std::lower_bound(this->pages.begin(), this->pages.end(), index, [](const std::shared_ptr<MemoryMap>& page, addr_t index) {
        return page->baseaddr() + page->size() <= index;
    });

    if (page == this->pages.end()) {
        throw std::runtime_error("MemoryMapModule: index out of range or there is a hole");
    }

    (*page)->set_at(index - (*page)->baseaddr(), value);
}

const std::string& MemoryMapModule::module_name() const {
    return this->mod_name;
}

const MemoryMapModule::SectionMapType& MemoryMapModule::get_sections() const {
    return this->sections;
}

void MemoryMapModule::flush() {
    for (auto& page: this->pages) {
        page->flush();
    }
}