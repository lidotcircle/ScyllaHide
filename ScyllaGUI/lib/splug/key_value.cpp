#include "scyllagui/splug/key_value.h"
#include <imgui.h>
using namespace std;

#define MAX_KEY_LEN 256
#define MAX_VALUE_LEN 4096


GuiSplugKeyValue::GuiSplugKeyValue(const YAML::Node& node) {
    if (!node.IsMap() && node.IsDefined() && !node.IsNull()) {
        throw std::runtime_error("GuiSplugKeyValue(): Node is not a map");
    }

    for (auto it = node.begin(); it != node.end(); ++it) {
        auto key = it->first.as<string>();
        auto value = it->second.as<string>();
        auto key_s   = shared_ptr<char>(new char[MAX_KEY_LEN], std::default_delete<char[]>());
        auto value_s = shared_ptr<char>(new char[MAX_VALUE_LEN], std::default_delete<char[]>());

        strncpy(key_s.get(), key.c_str(), MAX_KEY_LEN);
        strncpy(value_s.get(), value.c_str(), MAX_VALUE_LEN);
        KeyValueState state = {key_s, value_s, false, false};
        key_values.push_back(state);
    }
}

YAML::Node GuiSplugKeyValue::getNode() {
    YAML::Node node;

    for (auto it = key_values.begin(); it != key_values.end(); ++it) {
        string key(it->m_key.get());
        string value(it->m_value.get());
        if (key.empty())
            continue;

        node[key] = value;
    }

    return node;
}

bool GuiSplugKeyValue::show() {
    if (!this->visibility())
        return false;
    
    auto width = ImGui::GetWindowWidth();
    vector<size_t> delete_s;
    ImVec2 btn_size(20, 20);
    if (ImGui::BeginTable("##key_value_table", 3)) {
        ImGui::TableSetupColumn("键", ImGuiTableColumnFlags_WidthFixed, 0.4 * width);
        ImGui::TableSetupColumn("值", ImGuiTableColumnFlags_WidthFixed, 0.4 * width);
        ImGui::TableSetupColumn("操作",  ImGuiTableColumnFlags_WidthFixed, 0.2 * width);
        ImGui::TableHeadersRow();

        size_t i = 0;
        for (auto it = key_values.begin(); it != key_values.end(); ++it, i++) {
            if (it->m_delete) {
                delete_s.push_back(i);
                continue;
            }

            ImGui::PushID(i);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();

            if (it->m_editing) {
                ImGui::InputText("##key", it->m_key.get(), MAX_KEY_LEN);
                ImGui::TableNextColumn();
                ImGui::InputText("##value", it->m_value.get(), MAX_VALUE_LEN);
            } else {
                ImGui::Text("%s", it->m_key.get());
                ImGui::TableNextColumn();
                ImGui::Text("%s", it->m_value.get());
                if (ImGui::IsItemHovered()) {
                    ImGui::BeginTooltip();
                    ImGui::Text(it->m_value.get());
                    ImGui::EndTooltip();
                }
            }
            ImGui::TableNextColumn();

            if (it->m_editing) {
                if (ImGui::Button("S", btn_size)) {
                    it->m_editing = false;
                }
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("保存");
            } else {
                if (ImGui::Button("E", btn_size)) {
                    it->m_editing = true;
                }
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("编辑");
            }

            ImGui::SameLine();
            if (ImGui::Button("D", btn_size)) {
                it->m_delete = true;
            }
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("删除");

            ImGui::PopID();
        }
        ImGui::EndTable();
    }

    for (auto rit = delete_s.rbegin(); rit != delete_s.rend(); ++rit) {
        key_values.erase(key_values.begin() + *rit);
    }

    auto add_size = ImVec2(width * 0.4, 35);
    ImGui::Dummy(ImVec2((width - add_size.x) / 2, 0));
    ImGui::SameLine();
    if (ImGui::Button("新增", add_size)) {
        KeyValueState state;
        state.m_delete = false;
        state.m_editing = true;
        state.m_key = shared_ptr<char>(new char[MAX_KEY_LEN], std::default_delete<char[]>());
        state.m_key.get()[0] = '\0';
        state.m_value = shared_ptr<char>(new char[MAX_VALUE_LEN], std::default_delete<char[]>());
        state.m_value.get()[0] = '\0';
        key_values.push_back(state);
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("新增一个键值对");

    return true;
}
