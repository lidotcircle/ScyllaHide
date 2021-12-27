#ifndef _SCYLLA_GUI_YAML_NODE_H_
#define _SCYLLA_GUI_YAML_NODE_H_

#include <yaml-cpp/yaml.h>


class GuiYamlNode
{
private:
    bool m_visible;

public:
    virtual YAML::Node getNode() = 0;

    virtual bool show() = 0;
    bool& visibility();

    virtual ~GuiYamlNode();
};

#endif // _SCYLLA_GUI_YAML_NODE_H_