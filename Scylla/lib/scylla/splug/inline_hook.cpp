#include "scylla/splug/inline_hook.h"
#include <stdexcept>
#include <vector>
#include <tuple>
#include <regex>
using namespace std;

using addr_t = typename WinProcessNative::addr_t;

namespace scylla {

SPlugInlineHook::SPlugInlineHook(ScyllaContextPtr ctx): SPlug(ctx) {}

SPlugInlineHook::~SPlugInlineHook() {}

static inline bool strStartWith(const string& str, const string& prefix) {
    return str.compare(0, prefix.size(), prefix) == 0;
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
 *  note: address is a hexdecimal number which must start with 0x
 */
void SPlugInlineHook::doit(const YAML::Node& node) {
    if (!node.IsMap())
        throw runtime_error("inline hook rule should be a map");

    vector<tuple<addr_t,addr_t,string,string>> hooks;
    
    for (auto it=node.begin();it!=node.end();it++) {
        auto& key = it->first;
        auto& val = it->second;

        auto str = key.as<string>();
        if (strStartWith(str, "0x")) {
        }
    }
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