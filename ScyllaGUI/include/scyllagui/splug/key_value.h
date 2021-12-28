#ifndef _SCYLLA_GUI_SPLUG_KEY_VALUE_H_
#define _SCYLLA_GUI_SPLUG_KEY_VALUE_H_

#include "../yaml_node.h"
#include <vector>
#include <memory>

struct KeyValueState {
    std::shared_ptr<char> m_key;
    std::shared_ptr<char> m_value;
    bool m_delete;
    bool m_editing;
};

class GuiSplugKeyValue : public GuiYamlNode
{
private:
    std::vector<KeyValueState> key_values;

public:
    GuiSplugKeyValue(const YAML::Node& node);

    virtual YAML::Node getNode() override;

    virtual bool show() override;
};

#endif // _SCYLLA_GUI_SPLUG_KEY_VALUE_H_