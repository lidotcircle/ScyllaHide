#ifndef _SCYLLA_GUI_SPLUG_KEY_VALUE_H_
#define _SCYLLA_GUI_SPLUG_KEY_VALUE_H_

#include "../yaml_node.h"


class GuiSplugKeyValue : public GuiYamlNode
{
private:
public:
    GuiSplugKeyValue(const YAML::Node& node);

    virtual YAML::Node getNode() override;

    virtual bool show() override;
};

#endif // _SCYLLA_GUI_SPLUG_KEY_VALUE_H_