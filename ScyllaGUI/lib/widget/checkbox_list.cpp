#include "scyllagui/widget/checkbox_list.h"
#include <imgui.h>
using namespace std;


CheckboxList::CheckboxList(const YAML::Node& node, vector<tuple<string,string,bool>> checkbox_list):
    m_checkbox_list(move(checkbox_list))
{
    if (!node.IsMap())
        return;

    for (auto& item : m_checkbox_list) {
        auto default_val = get<2>(item);
        get<2>(item) = node[get<0>(item)].as<bool>(default_val);
    }
}

YAML::Node CheckboxList::getNode()
{
    YAML::Node node;
    for (auto& item : m_checkbox_list) {
        node[get<0>(item)] = get<2>(item);
    }
    return node;
}

bool CheckboxList::show()
{
    if (!this->visibility())
        return false;

    auto& io = ImGui::GetIO();
    for (auto& item: m_checkbox_list) {
        ImGui::Checkbox(get<1>(item).c_str(), &get<2>(item));

        if (ImGui::GetContentRegionAvailWidth() > 50)
            ImGui::SameLine();
    }

    return true;
}
