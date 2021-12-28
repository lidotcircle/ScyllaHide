#ifndef _SCYLLA_GUI_SPLUG_DLL_INJECTOR_H_
#define _SCYLLA_GUI_SPLUG_DLL_INJECTOR_H_

#include "../yaml_node.h"
#include <memory>
#include <vector>
#include <tuple>

struct DLLInjectState {
    bool enable;
    bool stealthy;
    bool deleted;
    std::shared_ptr<char> dll_path;
    std::shared_ptr<char> exchange;
};

class GuiSplugDllInjector : public GuiYamlNode
{
private:
    std::vector<DLLInjectState> m_dlls;

public:
    GuiSplugDllInjector(const YAML::Node& node);

    virtual YAML::Node getNode() override;

    virtual bool show() override;
};

#endif // _SCYLLA_GUI_SPLUG_DLL_INJECTOR_H_