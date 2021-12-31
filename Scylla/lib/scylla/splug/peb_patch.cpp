#include "scylla/splug/peb_patch.h"
#include "scylla/Peb.h"
#include "scylla/PebHider.h"
#include "scylla/NtApiShim.h"
#include <stdexcept>
using namespace std;
using namespace scylla;


namespace scylla {

SPlugPebPatch::SPlugPebPatch(ScyllaContextPtr context) : SPlug(context) {}

SPlugPebPatch::~SPlugPebPatch() {}

void SPlugPebPatch::doit(const YAML::Node& node) {
    if (node.IsNull())
        return;

    if (!node.IsMap())
        throw std::runtime_error("SPlugPebPatch::doit: node is not a map");

    auto& ctx = this->context();
    auto process = ctx->process();
    bool iswow64 = process->isWow64Process();

    auto peb = scl::GetPeb(process->rawhandle());
    if (peb == nullptr)
        throw std::runtime_error("SPlugPebPatch::doit: failed to get peb");
 
#ifndef _WIN64
    shared_ptr<scl::PEB64> peb64;
    if (iswow64) {
        peb64 = scl::Wow64GetPeb64(process->rawhandle());
        if (peb64 == nullptr)
            throw std::runtime_error("SPlugPebPatch::doit: failed to get peb64");
    }
#endif 
   
    if (node["BeingDebugged"].as<bool>(false)) {

        peb->BeingDebugged = FALSE;
#ifndef _WIN64
        if (iswow64)
            peb64->BeingDebugged = FALSE;
#endif
    }
    
    if (node["NtGlobalFlag"].as<bool>(false)) {
        peb->NtGlobalFlag &= ~0x70;
#ifndef _WIN64
        if (iswow64)
            peb64->NtGlobalFlag &= ~0x70;
#endif
    }
    
    if (node["ProcessParameters"].as<bool>(false)) {

        if (!scl::PebPatchProcessParameters(peb.get(), process->rawhandle()))
            throw std::runtime_error("SPlugPebPatch::doit: failed to patch process parameters");

#ifndef _WIN64
        if (iswow64 && !scl::Wow64Peb64PatchProcessParameters(peb64.get(), process->rawhandle())) {
            throw std::runtime_error("SPlugPebPatch::doit: failed to patch PEB64.ProcessParameters");
        }
#endif
    }

    if (node["HeapFlags"].as<bool>(false)) {
        if (!scl::PebPatchHeapFlags(peb.get(), process->rawhandle()))
            throw std::runtime_error("SPlugPebPatch::doit: failed to patch heap flags");

#ifndef _WIN64
        if (iswow64 && !scl::Wow64Peb64PatchHeapFlags(peb64.get(), process->rawhandle()))
            throw std::runtime_error("SPlugPebPatch::doit: failed to patch PEB64.HeapFlags");
#endif
    }

    if (node["OsBuildNumber"].as<bool>(false)) {
        peb->OSBuildNumber++;

#ifndef _WIN64
        if (iswow64)
            peb64->OSBuildNumber++;
#endif
    }

    if (!scl::SetPeb(process->rawhandle(), peb.get()))
        throw std::runtime_error("SPlugPebPatch::doit: failed to set peb");

#ifndef _WIN64
    if (iswow64 && !scl::Wow64SetPeb64(process->rawhandle(), peb64.get()))
        throw std::runtime_error("SPlugPebPatch::doit: failed to set peb64");
#endif
}

void SPlugPebPatch::undo() {}

} // namespace scylla