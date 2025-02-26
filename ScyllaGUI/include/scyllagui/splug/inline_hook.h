#ifndef _SCYLLA_GUI_SPLUG_INLINE_HOOK_H_
#define _SCYLLA_GUI_SPLUG_INLINE_HOOK_H_

#include "../yaml_node.h"
#include <memory>
#include <vector>
#include <string>
#include <map>


struct HookPairState {
private:
    std::string m_old_original;
    std::string m_old_hook;

public:
    HookPairState();
    void revalidate();

    std::shared_ptr<char> m_original;
    std::shared_ptr<char> m_hook;
    std::string m_remark;
    bool m_enable;
    bool m_valid;
    bool m_in_module;
    bool m_editing;
    bool m_delete;
};

struct HookModule {
    bool m_enable;
    std::vector<HookPairState> m_hooks;
};

class GuiSplugInlineHook : public GuiYamlNode
{
private:
    std::vector<HookPairState> m_hooks;
    std::map<std::string,HookModule> m_hooks_by_module;
    bool m_enable;

public:
    GuiSplugInlineHook(const YAML::Node& node);

    virtual YAML::Node getNode() override;

    virtual bool show() override;
};

#endif // _SCYLLA_GUI_SPLUG_INLINE_HOOK_H_