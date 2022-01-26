#ifndef _SCYLLA_GUI_SPLUG_IAT_HOOK_H_
#define _SCYLLA_GUI_SPLUG_IAT_HOOK_H_

#include "../yaml_node.h"
#include <memory>
#include <vector>
#include <string>
#include <map>


struct IATHookPairState {
private:
    std::string m_func;
    std::string m_target;

public:
    IATHookPairState();
    void revalidate();

    std::shared_ptr<char> m_func_mem;
    std::shared_ptr<char> m_target_mem;
    std::string m_remark;
    bool m_enable;
    bool m_valid;
    bool m_editing;
};

struct IATHookModule {
    bool m_enable;
    std::map<std::string,std::vector<IATHookPairState>> m_imports;
};

class GuiSplugIATHook : public GuiYamlNode
{
private:
    std::map<std::string,IATHookModule> m_modules;
    bool m_enable;

public:
    GuiSplugIATHook(const YAML::Node& node);

    virtual YAML::Node getNode() override;

    virtual bool show() override;
};

#endif // _SCYLLA_GUI_SPLUG_IAT_HOOK_H_