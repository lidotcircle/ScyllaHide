#include "process/map_pe_module.h"
#include "scylla/splug/dll_injector.h"
#include "scylla/splug/exchange.h"
#include <stdexcept>
using namespace std;
using namespace scylla;


namespace scylla {

SPlugExchange::SPlugExchange(ScyllaContextPtr context) : SPlug(context) {}

SPlugExchange::~SPlugExchange() {}

void SPlugExchange::doit(const YAML::Node& node) {
    if (!node.as<bool>(true))
        return;

    auto ctx = this->context();
    auto logger = ctx->log_client();
    auto& exch = ctx->exchange();
    auto process = ctx->process();
    auto inject_info = ctx->get_item<InjectDLLInfo>("__dll_injection");

    if (!inject_info)
        return;
    
    for (auto& dll : inject_info->dlls) {
        auto& mod = dll.first;
        auto& exch_name = dll.second;
        logger->info("write exchange data: %s::%s", mod.c_str(), exch_name.c_str());
        auto rmod = process->find_module(mod);
        if (rmod == nullptr)
            throw std::runtime_error("SPlugExchange::doit: module not found '" + mod + "'");

        // TODO resolve forwarder chain
        auto addr = rmod->baseaddr() + rmod->resolve_export(exch_name).m_rva;
        exch.dump_to_process(reinterpret_cast<void*>(addr));
    }
}

void SPlugExchange::undo() {
    // TODO
}

} // namespace scylla