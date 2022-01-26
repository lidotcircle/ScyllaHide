#ifndef _SPLUG_IAT_HOOK_H_
#define _SPLUG_IAT_HOOK_H_

#include "../splug.h"
#include "../../process/win_process_native.h"
#include <vector>

namespace scylla {

class SPlugIATHook : public SPlug
{
public:
    using patch_t = typename WinProcessNative::patch_t;

private:
    std::vector<patch_t> _patches;

public:
    SPlugIATHook(ScyllaContextPtr ctx);

    virtual void doit(const YAML::Node& node) override;
    virtual void undo() override;

    virtual ~SPlugIATHook() override;
};

} // namespace scylla

#endif // _SPLUG_IAT_HOOK_H_