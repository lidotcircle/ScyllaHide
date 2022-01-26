#include "scyllagui/splug/splug_view.h"
#include "scyllagui/splug/dll_injector.h"
#include "scyllagui/splug/exchange.h"
#include "scyllagui/splug/inline_hook.h"
#include "scyllagui/splug/iat_hook.h"
#include "scyllagui/splug/key_value.h"
#include "scyllagui/splug/log_server.h"
#include "scyllagui/splug/peb_patch.h"
#include <stdexcept>
using namespace std;


GuiSplugView::GuiSplugView(const YAML::Node& node, bool dbgplugin_mode):
    m_origin_node(node)
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

    this->add_child("pebPatch", "PEB", make_unique<GuiSplugPebPatch>(_node["pebPatch"]));
    this->add_child("dllInjector", "DLL注入", make_unique<GuiSplugDllInjector>(_node["dllInjector"], dbgplugin_mode));
    this->add_child("inlineHook", "Inline Hook", make_unique<GuiSplugInlineHook>(_node["inlineHook"]));
    this->add_child("IATHook", "IAT Hook", make_unique<GuiSplugIATHook>(_node["IATHook"]));
    this->add_child("keyValue", "键值配置", make_unique<GuiSplugKeyValue>(_node["keyValue"]));
    this->add_child("exchange", "Exchange", make_unique<GuiSplugExchange>(_node["exchange"]));
    this->add_child("logger", "日志服务", make_unique<GuiSplugLogServer>(_node["logger"]));
}

const YAML::Node& GuiSplugView::get_origin_node() const
{
    return m_origin_node;
}