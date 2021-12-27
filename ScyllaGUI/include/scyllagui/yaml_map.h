#ifndef _SCYLLA_GUI_YAML_MAP_H_
#define _SCYLLA_GUI_YAML_MAP_H_

#include "yaml_node.h"
#include <vector>
#include <string>
#include <memory>
#include <tuple>


class GuiYamlMap : public GuiYamlNode
{
private:
    std::vector<std::tuple<std::string,std::string,std::unique_ptr<GuiYamlNode>>> m_map;

public:
    virtual YAML::Node getNode() override;

    virtual bool show() override;

    void add_child(std::string key, std::string title, std::unique_ptr<GuiYamlNode> child);

    virtual ~GuiYamlMap() override;
};


#endif // _SCYLLA_GUI_YAML_MAP_H_