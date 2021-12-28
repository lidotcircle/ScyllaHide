#ifndef _SCYLLA_GUI_SPLUG_LOG_SERVER_H_
#define _SCYLLA_GUI_SPLUG_LOG_SERVER_H_

#include "../yaml_node.h"
#include <memory>


class GuiSplugLogServer : public GuiYamlNode
{
private:
    bool m_enable;
    int m_port;
    std::shared_ptr<char> m_addr;

public:
    GuiSplugLogServer(const YAML::Node& node);

    virtual YAML::Node getNode() override;

    virtual bool show() override;
};

#endif // _SCYLLA_GUI_SPLUG_LOG_SERVER_H_