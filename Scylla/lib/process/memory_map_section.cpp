#include "process/memory_map_section.h"
#include <algorithm>
#include <stdexcept>
#include <iostream>
using namespace std;


MemoryMapSection::MemoryMapSection(const std::string& sec_name, std::vector<std::shared_ptr<MemoryMap>> _pages):
    sec_name(sec_name), pages(std::move(_pages))
{
    if (this->pages.empty())
        throw std::runtime_error("MemoryMapSection::MemoryMapSection(): pages is empty");

    std::sort(this->pages.begin(), this->pages.end(), [](const std::shared_ptr<MemoryMap>& a, const std::shared_ptr<MemoryMap>& b) {
        return a->baseaddr() < b->baseaddr();
    });

    size_t prev_end = 0;
    size_t section_size = 0;
    for (auto& page : this->pages) {
        if (prev_end > 0 && page->baseaddr() != prev_end) {
            throw std::runtime_error("MemoryMapSection: pages are not continuous");
        }

        section_size += page->size();
        prev_end = page->baseaddr() + page->size();
    }
    this->sec_size = section_size;
    this->base_addr = this->pages.front()->baseaddr();
}

MemoryMapSection::addr_t MemoryMapSection::baseaddr() const {
    return this->base_addr;
}

size_t MemoryMapSection::size() const {
    return this->sec_size;
}

char MemoryMapSection::get_at(addr_t index) const {
    index += this->base_addr;
    auto page = std::lower_bound(this->pages.begin(), this->pages.end(), index, [](const std::shared_ptr<MemoryMap>& page, addr_t index) {
        return page->baseaddr() + page->size() <= index;
    });

    if (page == this->pages.end()) {
        throw std::runtime_error("MemoryMapSection: index out of range");
    }

    return (*page)->get_at(index - (*page)->baseaddr());
}

void MemoryMapSection::set_at(addr_t index, char value) {
    index += this->base_addr;
    auto page = std::lower_bound(this->pages.begin(), this->pages.end(), index, [](const std::shared_ptr<MemoryMap>& page, addr_t index) {
        return page->baseaddr() + page->size() <= index;
    });

    if (page == this->pages.end()) {
        throw std::runtime_error("MemoryMapSection: index out of range");
    }

    (*page)->set_at(index - (*page)->baseaddr(), value);
}

const std::string& MemoryMapSection::section_name() const {
    return this->sec_name;
}

void MemoryMapSection::flush() {
    for (auto& page: this->pages) {
        page->flush();
    }
}