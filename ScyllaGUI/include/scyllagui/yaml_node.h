#ifndef _SCYLLA_GUI_YAML_NODE_H_
#define _SCYLLA_GUI_YAML_NODE_H_

#include <yaml-cpp/yaml.h>
#include "./ui_element.h"


class GuiYamlNode: public UIElement
{
public:
    GuiYamlNode();

    virtual YAML::Node getNode() = 0;

    virtual ~GuiYamlNode() override;
};

#endif // _SCYLLA_GUI_YAML_NODE_H_