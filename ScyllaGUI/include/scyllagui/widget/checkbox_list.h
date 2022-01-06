#ifndef _CHECKBOX_LIST_H_
#define _CHECKBOX_LIST_H_

#include "../yaml_node.h"
#include <vector>
#include <string>
#include <tuple>


class CheckboxList : public GuiYamlNode
{
private:
    std::vector<std::tuple<std::string,std::string,bool>> m_checkbox_list;
    
public:
    CheckboxList(const YAML::Node& node, std::vector<std::tuple<std::string,std::string,bool>> checkbox_list);

    virtual YAML::Node getNode() override;

    virtual bool show() override;
};

#endif // _CHECKBOX_LIST_H_