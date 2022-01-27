#ifndef _SPLUG_DLL_INJECTOR_H_
#define _SPLUG_DLL_INJECTOR_H_

#include "../splug.h"
#include "../context_base.h"
#include <vector>
#include <string>


namespace scylla {

class SPlugDLLInjector: public SPlug {
public:
    SPlugDLLInjector(ScyllaContextPtr context);

    virtual void doit(const YAML::Node& node) override;
    virtual void undo() override;

    virtual ~SPlugDLLInjector() override;
};

struct InjectDLLInfo: public ScyllaContextItem {
    std::vector<std::pair<std::string, std::string>> dlls;

    InjectDLLInfo() = default;
    virtual ~InjectDLLInfo() override;
};

} // namespace scylla

#endif // _SPLUG_DLL_INJECTOR_H_