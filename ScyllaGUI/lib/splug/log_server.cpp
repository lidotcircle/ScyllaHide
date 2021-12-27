#include "scyllagui/splug/log_server.h"
#include <imgui.h>


GuiSplugLogServer::GuiSplugLogServer(const YAML::Node& node)
{
    m_enalbe = !node["disable"].as<bool>();
    m_port = node["port"].as<uint16_t>();
    m_addr = node["addr"].as<std::string>();
}

YAML::Node GuiSplugLogServer::getNode() {
    YAML::Node node;

    node["disable"] = !m_enalbe;
    node["port"] = m_port;
    node["addr"] = m_addr;

    return node;
}

bool GuiSplugLogServer::show() {
    if (!this->visibility())
        return false;

    if (this->m_port < 0 || this->m_port > 65535)
        this->m_port = 0;

    ImGui::Checkbox("Enable", &m_enalbe);
    ImGui::InputInt("Port 10-65535", &m_port);
    ImGui::InputText("Addr", m_addr.data(), m_addr.size());

    return true;
}