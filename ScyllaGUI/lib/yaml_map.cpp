#include "scyllagui/yaml_map.h"
#include <imgui.h>
#include <stdexcept>
using namespace std;


YAML::Node GuiYamlMap::getNode() {
    YAML::Node node;

    for (auto& pair : m_map) {
        auto& key = std::get<0>(pair);
        auto& child = std::get<2>(pair);
        node[key] = child->getNode();
    }

    return node;
}

bool GuiYamlMap::show() {
    if (!this->visibility())
        return false;
    
    for (auto& it : this->m_map) {
        const auto& title = get<1>(it);
        const auto& child = get<2>(it);

        if (ImGui::CollapsingHeader(title.c_str())) {
            child->show();
            ImGui::Spacing();
        }
    }

    return true;
}

void GuiYamlMap::add_child(std::string key, std::string title, std::unique_ptr<GuiYamlNode> child) {
    for (auto& it : this->m_map) {
        const auto& _key = get<0>(it);
        if (_key == key) {
            throw std::runtime_error("Duplicate key");
        }
    }

    m_map.push_back(make_tuple(key, title, move(child)));
}

GuiYamlMap::~GuiYamlMap() {}
