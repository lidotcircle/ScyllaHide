#include "process/map_pe_module.h"
#include "process/memory_map_slice_ref.h"
using namespace std;

MapPEModule::MapPEModule(): m_parsed(false) {}

MapPEModule::MapPEModule(const std::string& mod_name):
    mod_name(mod_name), m_parsed(false) {}

void MapPEModule::parse_header(PEHeader header) {
    m_header = header;
    m_parsed = true;
}

vector<string> MapPEModule::sections() const {
    vector<string> ret;
    for (auto& n: this->m_header.section_hdrs) {
        string name;
        for (auto& c: n.Name) {
            if (c == '\0')
                break;
            name += c;
        }
        ret.push_back(name);
    }
    return ret;
}

shared_ptr<MemoryMap> MapPEModule::section(const string& sec) {
    for (auto& n: this->m_header.section_hdrs) {
        string name;
        for (auto& c: n.Name) {
            if (c == '\0')
                break;
            name += c;
        }

        if (name == sec)
            return make_shared<MemoryMapSliceRef>(*this, n.VirtualAddress, n.Misc.VirtualSize);
    }

    return nullptr;
}

const shared_ptr<MemoryMap> MapPEModule::section(const string& sec) const {
    auto _this = const_cast<MapPEModule*>(this);
    return _this->section(sec);
}

const string& MapPEModule::module_name() const {
    return this->mod_name;
}

const PEHeader& MapPEModule::header() const {
    return this->m_header;
}
