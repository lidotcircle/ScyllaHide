#ifndef _SCYLLA_GUI_SPLUG_LOG_SERVER_H_
#define _SCYLLA_GUI_SPLUG_LOG_SERVER_H_

#include "../yaml_node.h"


class GuiSplugLogServer : public GuiYamlNode
{
private:
    bool m_enalbe;
    int m_port;
    std::string m_addr;

public:
    GuiSplugLogServer(const YAML::Node& node);

    virtual YAML::Node getNode() override;

    virtual bool show() override;
};

#endif // _SCYLLA_GUI_SPLUG_LOG_SERVER_H_