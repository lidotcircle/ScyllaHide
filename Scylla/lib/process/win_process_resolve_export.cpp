#include "process/memory_map_pefile.h"
#include "process/win_process_native.h"
#include <stdexcept>
using namespace std;


using addr_t = typename WinProcessNative::addr_t;


addr_t WinProcessNative::resolve_export(const std::string& module_name, const std::string& export_name) const
{
    auto mod = this->find_module(module_name);
    if (mod == nullptr)
        throw runtime_error("resolve_export(): module not found");
    
    auto entry = mod->resolve_export(export_name);
    return this->resolve_export(module_name, entry.m_ordinal);
}

addr_t WinProcessNative::resolve_export(const std::string& module_name, uint32_t ordinal) const
{
    auto mod = this->find_module(module_name);
    if (mod == nullptr)
        throw runtime_error("resolve_export(): module not found");
    
    auto entry = mod->resolve_export(ordinal);
    if (!entry.m_forwarder)
        return entry.m_rva + mod->baseaddr();
    
    if (entry.m_forwarder_symbol.empty())
        throw runtime_error("resolve_export(): forwarder symbol not found");
    
    auto spltpos = entry.m_forwarder_symbol.find(".");
    if (spltpos == string::npos)
        throw runtime_error("resolve_export(): invalid forwarder symbol");
    
    auto modname = entry.m_forwarder_symbol.substr(0, spltpos);
    if (this->find_module(modname) == nullptr)
        modname = modname + ".dll";
    auto export_name = entry.m_forwarder_symbol.substr(spltpos + 1);

    if (export_name.empty())
        throw runtime_error("resolve_export(): invalid forwarder symbol, no export name");
    
    if (export_name[0] == '#') {
        export_name.erase(export_name.begin());
        size_t idx = 0;
        auto ord = std::stoi(export_name, &idx);
        if (idx != export_name.size())
            throw runtime_error("resolve_export(): invalid forwarder symbol, invalid ordinal");

        return this->resolve_export(modname, ord);
    } else {

        return this->resolve_export(modname, export_name);
    }
}

addr_t WinProcessNative::resolve_export(const std::string& module_name, const std::regex& regex, std::string& symbol) const
{
    auto mod = this->find_module(module_name);
    if (mod == nullptr)
        throw runtime_error("resolve_export(): module not found");
    
    auto entry = mod->resolve_export(regex, symbol);
    return this->resolve_export(module_name, entry.m_ordinal);
}
