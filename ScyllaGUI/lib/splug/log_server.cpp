#include "scyllagui/splug/log_server.h"
#include <imgui.h>
using namespace std;

#define MAX_ADDR_LEN 256


GuiSplugLogServer::GuiSplugLogServer(const YAML::Node& node)
{
    m_enable = !node["disable"].as<bool>(false);
    m_port = node["udp_port"].as<uint16_t>(0);

    this->m_addr = shared_ptr<char>(new char[MAX_ADDR_LEN], std::default_delete<char[]>());
    string str = node["udp_addr"].as<std::string>("localhost");
    strncpy(this->m_addr.get(), str.c_str(), MAX_ADDR_LEN);
}

YAML::Node GuiSplugLogServer::getNode() {
    YAML::Node node;

    node["disable"] = !m_enable;
    node["udp_port"] = m_port;
    node["udp_addr"] = string(m_addr.get());

    return node;
}

bool GuiSplugLogServer::show() {
    if (!this->visibility())
        return false;

    if (this->m_port < 0 || this->m_port > 65535)
        this->m_port = 0;

    ImGui::Checkbox("开启", &m_enable);
    if (m_enable) {
        ImGui::InputInt("UDP端口", &m_port);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("如果设置为0，则使用随机端口, 建议设置为0");
        ImGui::InputText("UDP地址", m_addr.get(), MAX_ADDR_LEN);
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("ipv4 地址或者 localhost, 建议设置为localhost");
    }

    return true;
}