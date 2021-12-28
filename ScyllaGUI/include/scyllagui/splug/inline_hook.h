#ifndef _SCYLLA_GUI_SPLUG_INLINE_HOOK_H_
#define _SCYLLA_GUI_SPLUG_INLINE_HOOK_H_

#include "../yaml_node.h"
#include <memory>
#include <vector>
#include <string>
#include <map>


struct HookPairState {
    std::shared_ptr<char> m_original;
    std::shared_ptr<char> m_hook;
    bool m_editing;
    bool m_delete;
};

class GuiSplugInlineHook : public GuiYamlNode
{
private:
    std::vector<HookPairState> m_hooks;
    std::map<std::string,std::vector<HookPairState>> m_hooks_by_module;
    bool m_enable;

public:
    GuiSplugInlineHook(const YAML::Node& node);

    virtual YAML::Node getNode() override;

    virtual bool show() override;
};

#endif // _SCYLLA_GUI_SPLUG_INLINE_HOOK_H_