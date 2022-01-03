#ifndef _SCYLLA_GUI_SPLUG_DLL_INJECTOR_H_
#define _SCYLLA_GUI_SPLUG_DLL_INJECTOR_H_

#include "../yaml_node.h"
#include "../widget/peinfo_window.h"
#include <memory>
#include <vector>
#include <tuple>

struct DLLInjectState {
    bool enable;
    bool stealthy;
    bool deleted;
    bool is_internal;
    bool m_is_valid;
    PEInfoWindow m_info_window;
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