#ifndef _SPLUG_PEB_PATCH_H_
#define _SPLUG_PEB_PATCH_H_

#include "../splug.h"


namespace scylla {

class SPlugPebPatch : public SPlug {
public:
    SPlugPebPatch(ScyllaContextPtr context);

    virtual void doit(const YAML::Node& node) override;
    virtual void undo() override;

    virtual ~SPlugPebPatch() override;
};

} // namespace scylla

#endif // _SPLUG_PEB_PATCH_H_