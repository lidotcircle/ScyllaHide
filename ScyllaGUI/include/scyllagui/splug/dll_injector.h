#ifndef _SCYLLA_GUI_SPLUG_DLL_INJECTOR_H_
#define _SCYLLA_GUI_SPLUG_DLL_INJECTOR_H_

#include "../yaml_node.h"


class GuiSplugDllInjector : public GuiYamlNode
{
private:

public:
    GuiSplugDllInjector(const YAML::Node& node);

    virtual YAML::Node getNode() override;

    virtual bool show() override;
};

#endif // _SCYLLA_GUI_SPLUG_DLL_INJECTOR_H_