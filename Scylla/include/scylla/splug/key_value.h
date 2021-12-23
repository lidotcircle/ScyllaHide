#ifndef _SPLUG_KEY_VALUE_H_
#define _SPLUG_KEY_VALUE_H_

#include "../splug.h"


namespace scylla {

class SPlugKeyValue : public SPlug {
public:
    SPlugKeyValue(ScyllaContextPtr context);

    virtual void doit(const YAML::Node& node) override;
    virtual void undo() override;

    virtual ~SPlugKeyValue() override;
};

} // namespace scylla

#endif // _SPLUG_KEY_VALUE_H_