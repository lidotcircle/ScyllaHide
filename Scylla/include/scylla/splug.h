#ifndef _SCYLLA_SPLUG_H_
#define _SCYLLA_SPLUG_H_

#include "./context_base.h"
#include <yaml-cpp/yaml.h>


namespace scylla {

class SPlug {
private:
    ScyllaContextPtr m_context;

protected:
    ScyllaContextPtr context();
    const ScyllaContextPtr context() const;
    
public:
    SPlug() = delete;
    SPlug(ScyllaContextPtr context);

    virtual void doit(const YAML::Node& node) = 0;
    virtual void undo();

    virtual ~SPlug();
};

} // namespace scylla

#endif // _SCYLLA_SPLUG_H_