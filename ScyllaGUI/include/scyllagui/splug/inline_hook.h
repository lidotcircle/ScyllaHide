#ifndef _SCYLLA_GUI_SPLUG_INLINE_HOOK_H_
#define _SCYLLA_GUI_SPLUG_INLINE_HOOK_H_

#include "../yaml_node.h"


class GuiSplugInlineHook : public GuiYamlNode
{
private:
public:
    GuiSplugInlineHook(const YAML::Node& node);

    virtual YAML::Node getNode() override;

    virtual bool show() override;
};

#endif // _SCYLLA_GUI_SPLUG_INLINE_HOOK_H_