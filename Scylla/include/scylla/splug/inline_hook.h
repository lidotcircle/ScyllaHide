#ifndef _SPLUG_INLINE_HOOK_H_
#define _SPLUG_INLINE_HOOK_H_

#include "../splug.h"
#include "../../process/win_process_native.h"
#include <vector>

namespace scylla {

class SPlugInlineHook : public SPlug
{
public:
    using hook_t = typename WinProcessNative::hook_t;

private:
    std::vector<hook_t> _hooks;

public:
    SPlugInlineHook(ScyllaContextPtr ctx);

    virtual void doit(const YAML::Node& node) override;
    virtual void undo() override;

    virtual ~SPlugInlineHook() override;
};

} // namespace scylla

#endif // _SPLUG_INLINE_HOOK_H_