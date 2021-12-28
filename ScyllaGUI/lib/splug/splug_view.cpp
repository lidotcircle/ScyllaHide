#include "scyllagui/splug/splug_view.h"
#include "scyllagui/splug/dll_injector.h"
#include "scyllagui/splug/exchange.h"
#include "scyllagui/splug/inline_hook.h"
#include "scyllagui/splug/key_value.h"
#include "scyllagui/splug/log_server.h"
#include <stdexcept>
using namespace std;


GuiSplugView::GuiSplugView(const YAML::Node& node)
{
    if (!node.IsMap())
        throw runtime_error("GuiSplugView: node is not a map");

    this->add_child("dllInjector", "DLL Injection", make_unique<GuiSplugDllInjector>(node["dllInjector"]));
    this->add_child("inlineHook", "Inline Hook", make_unique<GuiSplugInlineHook>(node["inlineHook"]));
    this->add_child("keyValue", "Key Value", make_unique<GuiSplugKeyValue>(node["keyValue"]));
    this->add_child("exchange", "Exchange", make_unique<GuiSplugExchange>(node["exchange"]));
    this->add_child("logger", "Logger", make_unique<GuiSplugLogServer>(node["logger"]));
}