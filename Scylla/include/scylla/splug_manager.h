#ifndef _SCYLLA_SPLUG_MANAGER_H_
#define _SCYLLA_SPLUG_MANAGER_H_

#include "./splug.h"
#include "./context_base.h"
#include <memory>
#include <string>
#include <vector>
#include <string>
#include <functional>
#include <yaml-cpp/yaml.h>

namespace scylla {

using SPlugFactory = std::function<std::unique_ptr<SPlug>(ScyllaContextPtr)>;

class SPlugManager: public SPlug {
private:
    std::vector<std::pair<std::string,std::unique_ptr<SPlug>>> m_plugs;
    std::set<std::string> m_plugs_done;
    bool m_done;

public:
    SPlugManager() = delete;
    SPlugManager(ScyllaContextPtr context);

    void add_splug(const std::string& plugname, SPlugFactory plug_factory);
    virtual void doit(const YAML::Node& node) override;
    virtual void undo() override;
};

} // namespace scylla

#endif // _SCYLLA_SPLUG_MANAGER_H_