#ifndef _SCYLLA_GUI_SPLUG_DLL_INJECTOR_H_
#define _SCYLLA_GUI_SPLUG_DLL_INJECTOR_H_

#include "../yaml_node.h"
#include "../widget/peinfo_window.h"
#include <memory>
#include <vector>
#include <tuple>

struct DLLInjectState {
private:
    std::string m_old_dll_path;

public:
    bool enable;
    bool stealthy;
    bool deleted;
    bool is_internal;
    bool m_is_valid;
    PEInfoWindow m_info_window;
    std::shared_ptr<char> dll_path;
    std::shared_ptr<char> exchange;

    DLLInjectState();
    void refresh();
};

class GuiSplugDllInjector : public GuiYamlNode
{
private:
    std::vector<DLLInjectState> m_dlls;
    const bool m_dbgplugin_mode;

public:
    GuiSplugDllInjector(const YAML::Node& node, bool dbgplugin_mode);

    virtual YAML::Node getNode() override;

    virtual bool show() override;
};

#endif // _SCYLLA_GUI_SPLUG_DLL_INJECTOR_H_