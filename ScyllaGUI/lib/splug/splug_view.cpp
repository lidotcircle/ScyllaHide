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
    YAML::Node _node;

    if (node.IsNull()) {
        YAML::Node ep;
        _node["__"] = ep;
    } else {
        _node = node;
    }

    if (!_node.IsMap())
        throw runtime_error("GuiSplugView: node is not a map");

    this->add_child("dllInjector", "DLL Injection", make_unique<GuiSplugDllInjector>(_node["dllInjector"]));
    this->add_child("inlineHook", "Inline Hook", make_unique<GuiSplugInlineHook>(_node["inlineHook"]));
    this->add_child("keyValue", "Key Value", make_unique<GuiSplugKeyValue>(_node["keyValue"]));
    this->add_child("exchange", "Exchange", make_unique<GuiSplugExchange>(_node["exchange"]));
    this->add_child("logger", "Logger", make_unique<GuiSplugLogServer>(_node["logger"]));
}