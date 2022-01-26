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


static inline bool strStartWith(const string& str, const string& prefix) {
    return str.compare(0, prefix.size(), prefix) == 0;
}
static addr_t parseAddr(const string& str) {
    size_t len;
    addr_t addr = stoull(str, &len, 16);
    if (len != str.size())
        throw runtime_error("invalid address");

    return addr;
}

WinProcessNative::AddressExprInfo WinProcessNative::resolve_address_expression(const std::string& expr) const
{
    AddressExprInfo info;

    if (strStartWith(expr, "0x")) {
        info.addr = parseAddr(expr);
    } else if (expr.find("::") != string::npos) {
        info.module = expr.substr(0, expr.find("::"));
        auto ov = expr.substr(expr.find("::") + 2);
        auto rmod = this->find_module(info.module);
        if (!rmod)
            throw runtime_error("module '" + info.module + "'not found");

        // TODO resolve forwarder chain
        if (strStartWith(ov, "#")) {
            info.symbol = ov;
            size_t idx = 0;
            auto ordinal = stoul(ov.substr(1), &idx, 10);
            if (idx != ov.size())
                throw runtime_error("invalid ordinal");
            auto export_rva = rmod->resolve_export(ordinal).m_rva;
            info.addr = export_rva + rmod->baseaddr();
        } else {
            string truefunc;
            try {
                auto exp_entry = rmod->resolve_export(regex(ov, std::regex_constants::ECMAScript), truefunc);
                info.addr = rmod->baseaddr() + exp_entry.m_rva;
                info.symbol = truefunc;
            } catch (const exception& e) {
                throw runtime_error(expr + ": " + e.what());
            }
        }
    } else if (expr.find('#') != string::npos) {
        throw runtime_error("not implemented");
    } else if (expr.find('$') != string::npos) {
        info.module = expr.substr(0, expr.find('$'));
        auto offset = expr.substr(expr.find('$') + 1);
        auto rmod = this->find_module(info.module);
        if (!rmod)
            throw runtime_error("module '" + info.module + "'not found");

        info.addr = rmod->baseaddr() + parseAddr(offset);
    } else {
        throw runtime_error("invalid address expression '" + expr + "'");
    }

    return info;
}