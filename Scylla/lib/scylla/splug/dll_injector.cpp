#include "scylla/splug/dll_injector.h"
#include "hook_library.h"
#include "str_utils.h"
#include "scylla_constants.h"
#include <stdexcept>
using namespace std;
using namespace scylla;


namespace scylla {

const unsigned char* hook_library_data = hook_library;
const size_t         hook_library_data_size = sizeof(hook_library);


InjectDLLInfo::~InjectDLLInfo() {}


SPlugDLLInjector::SPlugDLLInjector(ScyllaContextPtr context) : SPlug(context) {}

SPlugDLLInjector::~SPlugDLLInjector() {}

void SPlugDLLInjector::doit(const YAML::Node& node) {
    if (!node.IsSequence())
        throw std::runtime_error("SPlugDLLInjector::doit: node is not a sequence");
    
    auto ctx = this->context();
    auto& exch = ctx->exchange();
    auto logger = ctx->log_client();
    auto process = ctx->process();
    auto inject_info = make_shared<InjectDLLInfo>();
    ctx->add_item("__dll_injection", inject_info);

    for (size_t i=0;i<node.size();i++) {
        auto& n = node[i];
        if (!n.IsMap())
            throw std::runtime_error("SPlugDLLInjector::doit: dll node is not a map");
        
        if (n["disable"].as<bool>(false))
            continue;

        auto path     = n["path"].as<string>();
        auto stealthy = n["stealthy"].as<bool>(false);
        auto exchange = n["exchange"].as<string>("");

        if (path.empty())
            throw std::runtime_error("SPlugDLLInjector::doit: dll path is empty");

        logger->info("injecting dll: %s, stealthy = %s", path.c_str(), stealthy ? "true" : "false");
        try {
            if (path == ANTIANTI_DLL) {
                process->inject_dll(hook_library_data, hook_library_data_size, path, stealthy);
            } else {
                process->inject_dll(path, stealthy);
            }
        } catch (exception& e) {
            logger->error("inject dll failed: %s", e.what());
            throw e;
        }
        logger->info("dll injected");

        auto mname = canonicalizeModuleName(path);
        inject_info->dlls.push_back(make_pair(mname, exchange));
    }
}

void SPlugDLLInjector::undo() {
    auto ctx = this->context();
    auto& exch = ctx->exchange();
    auto logger = ctx->log_client();
    auto process = ctx->process();
    auto inject_info = ctx->get_item<InjectDLLInfo>("__dll_injection");

    if (!inject_info) {
        logger->warn("no injection info");
        return;
    }

    logger->warn("uninjection not implemented");
    for (auto& dll : inject_info->dlls) {
        // TODO unload dll
    }

    ctx->remove_item("__dll_injection");
}

} // namespace scylla