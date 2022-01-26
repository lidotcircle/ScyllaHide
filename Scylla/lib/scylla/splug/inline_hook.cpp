#include "process/map_pe_module.h"
#include "scylla/splug/inline_hook.h"
#include "scylla_constants.h"
#include "utils.hpp"
#include <iostream>
#include <stdexcept>
#include <vector>
#include <tuple>
#include <regex>
#include <string>
using namespace std;

using addr_t = typename WinProcessNative::addr_t;

namespace scylla {

SPlugInlineHook::SPlugInlineHook(ScyllaContextPtr ctx): SPlug(ctx) {}

SPlugInlineHook::~SPlugInlineHook() {}

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
/**
 * Rule Spec:
 * 
 * 1. hook target
 *   1. a virtual address eg. 0x12345678
 *   2. module name and exported function name eg. "ntdll.dll::NtCreateFile",
 *      function name can be a regular expression
 *   3. module name and a file offset eg. "ntdll.dll#0x1234",
 *   4. module name and a relative virtual address eg. "ntdll.dll$0x1234",
 * 
 * 2. hooked target
 *   1. a virtual address eg. 0x12345678
 *   2. a module name and exported function name eg. "ntdll.dll::NtCreateFile",
 *      function name also can be a regular expression
 *   3. a module name and a file offset eg. "ntdll.dll#0x1234",
 *   4. a module name and a relative virtual address eg. "ntdll.dll$0x1234",
 *   5. for 2. and 3. and 4. hooked targets of in a module can be specified as a yaml map
 * 
 * 3. if hook target start with "//", it means the hook is disabled
 * 
 *  note: address is a hexdecimal number which must start with 0x
 */
void SPlugInlineHook::doit(const YAML::Node& node) {
    if (!node.IsMap() && node.IsDefined() && !node.IsNull())
        throw runtime_error("inline hook rule should be a map");

    if (node["disable"].as<bool>(false))
        return;

    auto ctx = this->context();
    auto logger = ctx->log_client();
    auto process = ctx->process();

    vector<tuple<addr_t,addr_t,string,string>> hooks;
    auto resolve_expr = [&](const string& expr) {
        addr_t addr;
        string mod, func;

        if (strStartWith(expr, "0x")) {
            addr = parseAddr(expr);
        } else if (expr.find('#') != string::npos) {
            throw runtime_error("not implemented");
        } else if (expr.find('$') != string::npos) {
            mod = expr.substr(0, expr.find('$'));
            auto offset = expr.substr(expr.find('$') + 1);
            auto rmod = process->find_module(mod);
            if (!rmod)
                throw runtime_error("module '" + mod + "'not found");

            addr = rmod->baseaddr() + parseAddr(offset);
        } else if (expr.find("::") != string::npos) {
            mod = expr.substr(0, expr.find("::"));
            func = expr.substr(expr.find("::") + 2);
            auto rmod = process->find_module(mod);
            if (!rmod)
                throw runtime_error("module '" + mod + "'not found");

            auto& exports = rmod->exports();
            string truefunc;

            try {
                // TODO resolve forwarder chain
                auto exp_entry = rmod->resolve_export(regex(func, std::regex_constants::ECMAScript), truefunc);
                addr = rmod->baseaddr() + exp_entry.m_rva;
                func = truefunc;
            } catch (const exception& e) {
                throw runtime_error(expr + ": " + e.what());
            }
        } else {
            throw runtime_error("invalid inline hook target '" + expr + "'");
        }

        return make_tuple(addr, mod, func);
    };
    auto add_hook = [&](const string& original_target, const YAML::Node& hook_target) {
        if (!hook_target.IsMap())
            throw runtime_error("hook target should be a map");

        if (hook_target["disable"].as<bool>(false))
            return;
        
        try {
            string hook_target_expr = hook_target["hook"].as<string>();
            auto original_info = resolve_expr(original_target);
            auto hook_info   = resolve_expr(hook_target_expr);
            hooks.push_back(
                make_tuple(get<0>(original_info), get<0>(hook_info), 
                           get<1>(original_info), get<2>(original_info)));
        logger->info("inline hook: %s(0x%s) -> %s(0x%s)",
                     original_target.c_str(), to_hexstring(get<0>(original_info)).c_str(),
                     hook_target_expr.c_str(), to_hexstring(get<0>(hook_info)).c_str());
        } catch (const exception& e) {
            throw runtime_error("inline hook rule error: " + string(e.what()));
        }
    };
    
    for (auto it=node.begin();it!=node.end();it++) {
        auto& key = it->first;
        auto& val = it->second;

        auto str = key.as<string>();
        if (str == "disable")
            continue;

        const bool not_module = str.find("::") != string::npos || 
                                str.find('#') != string::npos || 
                                str.find('$') != string::npos;

        if (not_module) {
            add_hook(str, val);
        } else {
            if (val["disable"].as<bool>(false))
                continue;

            for (auto it=val.begin();it!=val.end();it++) {
                string kn = str;
                auto k = it->first.as<string>();
                if (k == "disable")
                    continue;

                auto v = it->second;
                if (strStartWith(k, "$") || strStartWith(k, "#")) {
                    kn = kn + k;
                } else {
                    kn = kn + "::" + k;
                }

                add_hook(kn, v);
            }
        }
    }

    auto& exch = ctx->exchange();
    for (auto& hook: hooks) {
        auto original_addr = get<0>(hook);
        auto hook_addr     = get<1>(hook);
        auto original_mod  = get<2>(hook);
        auto original_func = get<3>(hook);

        auto hh = process->hook(original_addr, hook_addr);
        exch.add_entry(original_mod, original_func, reinterpret_cast<void*>(original_addr), hh->trampoline());
        this->_hooks.push_back(std::move(hh));
    }
}

void SPlugInlineHook::undo() {
    auto ctx = this->context();
    auto& exch = ctx->exchange();
    auto process = ctx->process();

    for (auto& hk : _hooks) {
        if (hk) {
            exch.remove_entry_by_trampoline(hk->trampoline());
            process->unhook(std::move(hk));
        }
    }

    this->_hooks.clear();
}

} // namespace scylla