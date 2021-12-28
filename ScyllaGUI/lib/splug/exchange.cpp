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
    ImGui::Checkbox("Enable exchange", &this->enable_exchange);
    return true;
}
