#include "process/memory_map_module.h"
#include "process/memory_map_section.h"
#include "process/pe_header.h"
#include "str_utils.h"
#include <algorithm>
#include <map>
#include <string>
#include <stdexcept>
using namespace std;


using addr_t = typename MemoryMapModule::addr_t;

MemoryMapModule::MemoryMapModule(const std::string& mod_name, PEHeader header, std::vector<std::shared_ptr<MemoryMap>> _pages):
    MapPEModule(mod_name), pages(std::move(_pages))
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

    this->parse_header(header);
}

MemoryMapModule::addr_t MemoryMapModule::baseaddr() const {
    return this->base_addr;
}

size_t MemoryMapModule::size() const {
    return this->mod_size;
}

char MemoryMapModule::get_at(addr_t index) const {
   index += this->base_addr;
    auto ipage = std::upper_bound(this->pages.begin(), this->pages.end(), index, [](addr_t index, const std::shared_ptr<MemoryMap>& page) {
        return page->baseaddr() + page->size() > index;
    });

    if (ipage == this->pages.end())
        throw std::runtime_error(
            strformat("MemoryMapModule::get_at(0x%x): index out of range or there is a hole", index));

    auto page = *ipage;
    if (page->baseaddr() > index || page->baseaddr() + page->size() <= index)
        throw std::runtime_error(
            strformat("MemoryMapModule::get_at(0x%x): index out of range or there is a hole", index));

    return page->get_at(index - page->baseaddr());
}

void MemoryMapModule::set_at(addr_t index, char value) {
    index += this->base_addr;
    auto ipage = std::upper_bound(this->pages.begin(), this->pages.end(), index, [](addr_t index, const std::shared_ptr<MemoryMap>& page) {
        return page->baseaddr() + page->size() > index;
    });

    if (ipage == this->pages.end())
        throw std::runtime_error(
            strformat("MemoryMapModule::set_at(0x%x): index out of range or there is a hole", index));

    auto page = *ipage;
    if (page->baseaddr() > index || page->baseaddr() + page->size() <= index)
        throw std::runtime_error(
            strformat("MemoryMapModule::set_at(0x%x): index out of range or there is a hole", index));

    page->set_at(index - page->baseaddr(), value);
}

MemoryMapModule::SectionMapType& MemoryMapModule::get_sections() {
    return this->sections;
}
const MemoryMapModule::SectionMapType& MemoryMapModule::get_sections() const {
    return this->sections;
}

void MemoryMapModule::flush() {
    for (auto& page: this->pages) {
        page->flush();
    }
}