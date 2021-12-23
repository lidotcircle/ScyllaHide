#include "scylla/splug/dll_injector.h"
#include <stdexcept>
using namespace std;
using namespace scylla;


namespace scylla {

InjectDLLInfo::~InjectDLLInfo() {}


SPlugDLLInjector::SPlugDLLInjector(ScyllaContextPtr context) : SPlug(context) {}

SPlugDLLInjector::~SPlugDLLInjector() {}

void SPlugDLLInjector::doit(const YAML::Node& node) {
    if (!node.IsSequence())
        throw std::runtime_error("SPlugDLLInjector::doit: node is not a sequence");
    
    auto ctx = this->context();
    auto& exch = ctx->exchange();
    auto process = ctx->process();
    auto inject_info = make_shared<InjectDLLInfo>();
    ctx->add_item("__dll_injection", inject_info);

    for (size_t i=0;i<node.size();i++) {
        auto& n = node[i];
        if (!n.IsMap())
            throw std::runtime_error("SPlugDLLInjector::doit: dll node is not a map");

        auto path     = n["path"].as<string>();
        auto stealthy = n["stealthy"].as<bool>(false);
        auto exchange = n["exchange"].as<string>("");

        if (path.empty())
            throw std::runtime_error("SPlugDLLInjector::doit: dll path is empty");
        
        process->inject_dll(path, stealthy);
        inject_info->dlls.push_back(make_pair(path, exchange));
    }
}

void SPlugDLLInjector::undo() {
    auto ctx = this->context();
    auto& exch = ctx->exchange();
    auto process = ctx->process();
    auto inject_info = ctx->get_item<InjectDLLInfo>("__dll_injection");

    if (!inject_info)
        return;

    for (auto& dll : inject_info->dlls) {
        // TODO unload dll
    }

    ctx->remove_item("__dll_injection");
}

} // namespace scylla