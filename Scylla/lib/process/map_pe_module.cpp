#include "process/map_pe_module.h"
#include "process/memory_map_slice_ref.h"
#include <stdexcept>
#include <iostream>
#include <regex>
using namespace std;
using namespace peparse;

using addr_t = typename MapPEModule::addr_t;
using ExportEntry = typename MapPEModule::ExportEntry;

ImportEntry::ImportEntry(uint16_t ordinal)
{
    m_ordinal.is_ordinal = true;
    m_ordinal.ordinal = ordinal;
}
ImportEntry::ImportEntry(const string& name)
{
    m_name.is_ordinal = false;
    m_name.name = new string(name);
}
ImportEntry::~ImportEntry() {
    if (!m_name.is_ordinal) {
        delete m_name.name;
    }
}

ImportEntry::ImportEntry(ImportEntry&& other)
{
    if (other.is_ordinal()) {
        m_ordinal = other.m_ordinal;
    } else {
        m_name = other.m_name;
        other.m_name.name = new string();
    }
}
ImportEntry::ImportEntry(const ImportEntry& other)
{
    if (other.is_ordinal()) {
        m_ordinal = other.m_ordinal;
    } else {
        m_name = other.m_name;
        m_name.name = new string(*m_name.name);
    }
}

ImportEntry& ImportEntry::operator=(const ImportEntry& other)
{
    this->~ImportEntry();

    if (other.is_ordinal()) {
        m_ordinal = other.m_ordinal;
    } else {
        m_name = other.m_name;
        m_name.name = new string(*m_name.name);
    }
    return *this;
}
ImportEntry& ImportEntry::operator=(ImportEntry&& other)
{
    this->~ImportEntry();

    if (other.is_ordinal()) {
        m_ordinal = other.m_ordinal;
    } else {
        m_name = other.m_name;
        other.m_name.name = new string();
    }
    return *this;
}

bool ImportEntry::operator<(const ImportEntry& other) const
{
    if (m_ordinal.is_ordinal) {
        if (other.m_ordinal.is_ordinal) {
            return m_ordinal.ordinal < other.m_ordinal.ordinal;
        } else {
            return true;
        }
    } else {
        if (other.m_ordinal.is_ordinal) {
            return false;
        } else {
            return *m_name.name < *other.m_name.name;
        }
    }
}

bool ImportEntry::operator==(const ImportEntry& other) const
{
    if (m_ordinal.is_ordinal) {
        if (other.m_ordinal.is_ordinal) {
            return m_ordinal.ordinal == other.m_ordinal.ordinal;
        } else {
            return false;
        }
    } else {
        if (other.m_ordinal.is_ordinal) {
            return false;
        } else {
            return *m_name.name == *other.m_name.name;
        }
    }
}

bool ImportEntry::operator!=(const ImportEntry& other) const
{
    return !(*this == other);
}

string ImportEntry::symbolname() const {
    if (m_ordinal.is_ordinal) {
        throw std::runtime_error("ImportEntry::symbolname(): not a name");
    } else {
        return *this->m_name.name;
    }
}

uint16_t ImportEntry::ordinal() const {
    if (m_ordinal.is_ordinal) {
        return m_ordinal.ordinal;
    } else {
        throw std::runtime_error("ImportEntry::ordinal(): not an ordinal");
    }
}

bool ImportEntry::is_ordinal() const {
    return m_ordinal.is_ordinal;
}

MapPEModule::MapPEModule(): m_parsed(false) {}

MapPEModule::MapPEModule(const std::string& mod_name):
    mod_name(mod_name), m_parsed(false) {}

void MapPEModule::parse_header(PEHeader header) {
    m_header = header;
    m_parsed = true;
}

void MapPEModule::change_base(addr_t base) {
    throw std::runtime_error("MapPEModule::change_base(): not implemented");
}

vector<string> MapPEModule::sections() const {
    if (!m_parsed)
        throw runtime_error("MapPEModule::sections() called before header parsed");

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
    if (!m_parsed)
        throw runtime_error("PEModule not parsed");

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
    if (!m_parsed)
        throw runtime_error("PE header not parsed");

    return this->m_header;
}

const map<uint32_t,ExportEntry>& MapPEModule::exports() const {
    if (!this->m_parsed)
        throw runtime_error("Parsing not done yet");

    if (this->m_exports)
        return *this->m_exports;

    const auto& exp_dir = this->m_header.directory_export();
    if (exp_dir.VirtualAddress == 0) {
        auto _this = const_cast<MapPEModule*>(this);
        _this->m_exports = make_shared<map<uint32_t,ExportEntry>>();
        return *this->m_exports;
    }

    export_dir_table exp_table;
    for (size_t i=0;i<sizeof(exp_table);i++) {
        char c = this->get_at(exp_dir.VirtualAddress + i);
        ((char*)&exp_table)[i] = c;
    }

    auto& export_directory = this->header().directory_export();
    auto export_beg = export_directory.VirtualAddress;
    auto export_end = export_beg + export_directory.Size;

    map<uint32_t,ExportEntry> ret;
    auto numOfEntries = exp_table.AddressTableEntries;
    auto addrTableRVA = exp_table.ExportAddressTableRVA;
    for (uint32_t i=0;i<numOfEntries;i++) {
        auto export_rva = this->get_u32(addrTableRVA + i * 4);
        ExportEntry e_entry;
        e_entry.m_rva = export_rva;
        e_entry.m_ordinal = i + exp_table.OrdinalBase;
        e_entry.m_forwarder = export_rva >= export_beg && export_rva < export_end;
        if (e_entry.m_forwarder) {
            auto sym = this->get_nullterm_string(e_entry.m_rva);
            if (sym.empty())
                throw std::runtime_error("Forwarder symbol is empty");

            e_entry.m_forwarder_symbol = sym;
        }

        ret[i + exp_table.OrdinalBase] = e_entry;
    }

    auto numOfNames = exp_table.NumberOfNamePointers;
    auto namePtrRVA = exp_table.NamePointerRVA;
    auto OrdTableRVA = exp_table.OrdinalTableRVA;
    for (size_t i=0;i<numOfNames;i++) {
        auto name_ptr = this->get_u32(namePtrRVA + i * 4);
        auto ord      = this->get_u16(OrdTableRVA + i * 2);

        if (ord >= ret.size()) {
            cerr << "Warning: ordinal out of range: " << ord << endl;
            continue;
        }

        const string name = this->get_nullterm_string(name_ptr);
        if (name.empty()) {
            cerr << "Warning: empty name for export " << i << endl;
            continue;
        }

        ret[ord + exp_table.OrdinalBase].m_name = name;
    }

    auto _this = const_cast<MapPEModule*>(this);
    _this->m_exports = make_shared<map<uint32_t,ExportEntry>>(move(ret));
    return *_this->m_exports;
}

ExportEntry MapPEModule::resolve_export(const std::string& name) const {
    auto& exports = this->exports();
    for (auto& e: exports) {
        if (e.second.m_name == name)
            return e.second;
    }

    throw runtime_error("export symbol '" + name + "' not found");
}

ExportEntry MapPEModule::resolve_export(const regex& re, string& symbol) const {
    auto& exports = this->exports();
    bool found = false;
    ExportEntry ret;

    for (auto& e: exports) {
        if (std::regex_match(e.second.m_name, re)) {
            if (found)
                throw runtime_error("multiple symbols match regex");
            ret = e.second;
            found = true;
        }
    }

    if (!found)
        throw runtime_error("export symbol regex not found");
    
    return ret;
}

ExportEntry MapPEModule::resolve_export(uint32_t ordinal) const {
    auto& exports = this->exports();
    if (exports.find(ordinal) == exports.end())
        throw runtime_error("export ordinal " + to_string(ordinal) + " not found");

    return exports.at(ordinal);
}
 
const map<string,map<ImportEntry,addr_t>>& MapPEModule::imports() const {
    if (!this->m_parsed)
        throw runtime_error("Parsing not done yet");

    if (this->m_imports)
        return *this->m_imports;

    map<string,map<ImportEntry,addr_t>> result;
    auto imp_dir = this->m_header.directory_import();
    if (imp_dir.VirtualAddress == 0) {
        auto _this = const_cast<MapPEModule*>(this);
        _this->m_imports = make_shared<map<string,map<ImportEntry,addr_t>>>(result);
        return *_this->m_imports;
    }

    auto imp_rva = imp_dir.VirtualAddress;
    import_dir_entry imp_entry;
    string dllname;

    const auto add_dllimport = [&](const import_dir_entry& entry, map<ImportEntry,addr_t>& imports) {
        auto rva = entry.LookupTableRVA;
        auto addr_rva = entry.AddressRVA;
        auto size = this->header().is_64bit() ? sizeof(uint64_t) : sizeof(uint32_t);

        for(;;rva += size, addr_rva += size) {
            uint64_t tbl = 0;
            bool is_ordinal = false;
            if (this->header().is_64bit()) {
                tbl = this->get_u64(rva);
                if (tbl >> 63) {
                    is_ordinal = true;
                    tbl &= 0x7FFFFFFFFFFFFFFF;
                }
            } else {
                tbl = this->get_u32(rva);
                if (tbl >> 31) {
                    is_ordinal = true;
                    tbl &= 0x7FFFFFFF;
                }
            }

            if (tbl == 0)
                return;

            if (is_ordinal) {
                uint16_t ord = tbl & 0xFFFF;
                imports.insert(make_pair(ImportEntry(ord), addr_rva));
            } else {
                uint32_t namerva = tbl & 0x7FFFFFFF;
                namerva += 2; // skip hint
                string iname;
                for (;;namerva += 1) {
                    char c = this->get_at(namerva);
                    if (c == '\0')
                        break;
                    iname.push_back(c);
                }
                imports.insert(make_pair(ImportEntry(iname), addr_rva));
            }
        }
    };

    for (;;imp_rva += sizeof(imp_entry)) {
        dllname.clear();
        for (size_t i=0;i<sizeof(imp_entry);i++) {
            char c = this->get_at(imp_rva + i);
            ((char*)&imp_entry)[i] = c;
        }

        if (imp_entry.NameRVA == 0)
            break;

        for (size_t i=0;;i++) {
            auto c = this->get_at(imp_entry.NameRVA + i);
            if (c == '\0')
                break;
            dllname += c;
        }

        map<ImportEntry,addr_t> dllimport;
        add_dllimport(imp_entry, dllimport);
        result[dllname] = dllimport;
    }

    auto _this = const_cast<MapPEModule*>(this);
    _this->m_imports = make_shared<map<string,map<ImportEntry,addr_t>>>(result);
    return *_this->m_imports;
}

bool MapPEModule::relocatable() const {
    uint16_t dllchara;
    if (this->header().is_64bit())
        dllchara = this->m_header.nthdr.optional_hdr.optional_hdr64.DllCharacteristics;
    else
        dllchara = this->m_header.nthdr.optional_hdr.optional_hdr32.DllCharacteristics;

    return dllchara & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
}

void MapPEModule::base_relocate(addr_t newbase) {
    auto oldbase = this->baseaddr();
    this->change_base(newbase);
    int64_t delta = newbase - oldbase;

    auto reloc_dir = this->header().directory_basereloc();
    if (reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0)
        return;

    reloc_block reloc = { 0 };
    addr_t rva = reloc_dir.VirtualAddress;

    for (;;) {
        for (size_t i=0;i<sizeof(reloc);i++) {
            char c = this->get_at(rva + i);
            ((char*)&reloc)[i] = c;
        }

        if (reloc.PageRVA == 0)
            break;

        if (reloc.BlockSize < sizeof(reloc))
            throw runtime_error("Invalid relocation block size");

        size_t count = (reloc.BlockSize - sizeof(reloc)) / sizeof(uint16_t);
        vector<uint16_t> relocInfos;
        for (size_t i=0;i<count;i++) {
            uint16_t ri = this->get_u16(rva + sizeof(reloc) + i * sizeof(uint16_t));
            relocInfos.push_back(ri);
        }

        for (auto ri: relocInfos) {
            auto type = ri >> 12;
            auto offset = ri & 0xfff;

            switch (type)
            {
            case RELOC_ABSOLUTE:
                break;
            case RELOC_HIGHLOW:
            case RELOC_DIR64: {
                int32_t patchAddress = reloc.PageRVA + offset;
                if (patchAddress <= 0)
                    throw runtime_error("Invalid relocation address");
                
                if (this->header().is_64bit()) {
                    int64_t value = this->get_u64(patchAddress);
                    value += delta;
                    this->set_u64(patchAddress, value);
                } else {
                    int32_t value = this->get_u32(patchAddress);
                    value += (int32_t)delta;
                    this->set_u32(patchAddress, value);
                }
            } break;
            default:
                break;
            }
        }

        rva += reloc.BlockSize;
    }

    this->flush();
}