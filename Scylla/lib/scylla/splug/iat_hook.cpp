#include "process/map_pe_module.h"
#include "scylla/splug/iat_hook.h"
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

SPlugIATHook::SPlugIATHook(ScyllaContextPtr ctx): SPlug(ctx) {}

SPlugIATHook::~SPlugIATHook() {}

void SPlugIATHook::doit(const YAML::Node& node) {
    if (!node.IsMap() && node.IsDefined() && !node.IsNull())
        throw runtime_error("inline hook rule should be a map");

    if (node["disable"].as<bool>(false))
        return;

    auto ctx = this->context();
    auto logger = ctx->log_client();
    auto process = ctx->process();

    for (auto it=node.begin();it!=node.end();it++) {
        auto& key = it->first;
        auto& val = it->second;

        auto dllmod = key.as<string>();
        if (dllmod == "disable")
            continue;
        
        if (val.IsNull())
            continue;
        
        if (!val.IsMap())
            throw runtime_error("expect a map for IAT hook module " + dllmod);

        if (val["disable"].as<bool>(false))
            continue;
        
        auto mod = process->find_module(dllmod);
        if (mod == nullptr)
            throw runtime_error("SPlugIATHook::doti: can't find module " + dllmod);
        auto& imports = mod->imports();

        for (auto it2=val.begin();it2!=val.end();it2++) {
            auto& key2 = it2->first;
            auto& val2 = it2->second;
            
            auto impmod = key2.as<string>();
            std::transform(impmod.begin(), impmod.end(), impmod.begin(), ::tolower);
            if (impmod == "disable")
                continue;
            
            if (val2.IsNull())
                continue;
            
            if (!val2.IsMap())
                throw runtime_error("expect a map for IAT hook function " + dllmod + "::" + impmod);

            if (imports.find(impmod) == imports.end())
                throw runtime_error("SPlugIATHook::doti: can't find import " + dllmod + "::" + impmod);
            
            const auto& funcs = imports.at(impmod);
            for (auto it3=val2.begin();it3!=val2.end();it3++) {
                auto& key3 = it3->first;
                auto& val3 = it3->second;

                auto impfunc = key3.as<string>();
                ImportEntry ie(impfunc);
                if (impfunc.find('#') == 0) {
                    size_t idx = 0;
                    auto ordinal = std::stoi(impfunc.substr(1), &idx);
                    if (idx != impfunc.size() - 1)
                        throw runtime_error("SPlugIATHook::doti: invalid ordinal " + impfunc);
                    ie = ImportEntry(ordinal);
                }

                if (funcs.find(ie) == funcs.end())
                    throw runtime_error("SPlugIATHook::doti: can't find import function " + dllmod + "::" + impmod + "::" + impfunc);

                auto entry = funcs.at(ie);

                if (!val3.IsMap())
                    throw runtime_error("expect a map for IAT hook function " + dllmod + "::" + impmod + "::" + impfunc);
                
                if (val3["disable"].as<bool>(false))
                    continue;
                
                auto n = val3["hook"].as<string>();
                auto hookaddr = process->resolve_address_expression(n);
                _patches.push_back(process->patch(entry, hookaddr.addr));
                logger->info("IAT Hook: %s::%s::%s -> %s", dllmod.c_str(), impmod.c_str(), impfunc.c_str(), n.c_str());
            }
        }
    }
}

void SPlugIATHook::undo() {
    auto ctx = this->context();
    auto process = ctx->process();

    for (auto& pt : _patches) {
        if (pt)
            process->unpatch(move(pt));
    }

    this->_patches.clear();
}

} // namespace scylla