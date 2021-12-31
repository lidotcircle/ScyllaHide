#ifndef _SCYLLA_GUI_SPLUG_PEB_PATCH_H_
#define _SCYLLA_GUI_SPLUG_PEB_PATCH_H_

#include "../yaml_node.h"
#include <vector>
#include <memory>

class GuiSplugPebPatch : public GuiYamlNode
{
private:
    bool m_being_debugged;
    bool m_ntglobal_flag;
    bool m_process_parameters;
    bool m_heap_flags;
    bool m_osbuild_number;

public:
    GuiSplugPebPatch(const YAML::Node& node);

    virtual YAML::Node getNode() override;

    virtual bool show() override;
};

#endif // _SCYLLA_GUI_SPLUG_PEB_PATCH_H_