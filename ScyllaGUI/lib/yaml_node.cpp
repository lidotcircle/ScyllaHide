#include "scyllagui/yaml_node.h"


GuiYamlNode::GuiYamlNode(): m_visible(true) {}

bool& GuiYamlNode::visibility() {
    return this->m_visible;
}

GuiYamlNode::~GuiYamlNode() {}
