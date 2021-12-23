#include "scylla/splug/inline_hook.h"
using namespace std;

namespace scylla {

SPlugInlineHook::SPlugInlineHook(ScyllaContextPtr ctx): SPlug(ctx) {}

SPlugInlineHook::~SPlugInlineHook() {}

void SPlugInlineHook::doit(const YAML::Node& node) {
    // TODO
}

void SPlugInlineHook::undo() {
    auto ctx = this->context();
    auto process = ctx->process();

    for (auto& hook_t : _hooks) {
        if (hook_t)
            process->unhook(std::move(hook_t));
    }

    this->_hooks.clear();
}

} // namespace scylla