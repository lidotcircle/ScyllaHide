#ifndef _SPLUG_EXCHANGE_H_
#define _SPLUG_EXCHANGE_H_

#include "../splug.h"


namespace scylla {

class SPlugExchange: public SPlug {
public:
    SPlugExchange(ScyllaContextPtr context);

    virtual void doit(const YAML::Node& node) override;
    virtual void undo() override;

    virtual ~SPlugExchange() override;
};

} // namespace scylla

#endif // _SPLUG_EXCHANGE_H_