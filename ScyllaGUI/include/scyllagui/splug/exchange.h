#ifndef _SCYLLA_GUI_SPLUG_EXCHANGE_H_
#define _SCYLLA_GUI_SPLUG_EXCHANGE_H_

#include "../yaml_node.h"


class GuiSplugExchange : public GuiYamlNode
{
private:
    std::vector<std::pair<std::string,std::string>> m_exchange;
    
public:
    GuiSplugExchange(const YAML::Node& node);

    virtual YAML::Node getNode() override;

    virtual bool show() override;
};

#endif // _SCYLLA_GUI_SPLUG_EXCHANGE_H_