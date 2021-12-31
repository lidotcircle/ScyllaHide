#include "scyllagui/splug/exchange.h"
#include <imgui.h>
using namespace std;


GuiSplugExchange::GuiSplugExchange(const YAML::Node& node)
{
    this->enable_exchange = node.as<bool>(true);
}

YAML::Node GuiSplugExchange::getNode() {
    YAML::Node node;
    node = this->enable_exchange;
    return node;
}

bool GuiSplugExchange::show() {
    ImGui::Checkbox("开启 exchange 写入", &this->enable_exchange);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("将hook、配置、日志端口等信息, 写入到注入的DLL中");
    return true;
}
