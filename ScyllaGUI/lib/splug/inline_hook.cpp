#include "scyllagui/splug/inline_hook.h"
#include "scylla_constants.h"
#include "str_utils.h"
#include <stdexcept>
#include <regex>
#include <imgui.h>
using namespace std;

#define MAX_TARGET_LEN 1024

HookPairState::HookPairState()
{
    m_original = shared_ptr<char>(new char[MAX_TARGET_LEN], std::default_delete<char[]>());
    m_hook = shared_ptr<char>(new char[MAX_TARGET_LEN], std::default_delete<char[]>());
    m_original.get()[0] = '\0';
    m_hook.get()[0] = '\0';
    m_enable = true;
    m_valid = false;
    m_in_module = false;
    m_editing = false;
    m_delete = false;
}

void HookPairState::revalidate() {
    if (_strnicmp(m_original.get(), this->m_old_original.c_str(), MAX_TARGET_LEN) == 0 &&
        _strnicmp(m_hook.get(), this->m_old_hook.c_str(), MAX_TARGET_LEN) == 0)
    {
        return;
    }

    this->m_old_original = m_original.get();
    this->m_old_hook = m_hook.get();

    static std::regex rx("^.+(::.+|\\$0x[0-9A-Fa-f]+|\\#0x[0-9A-Fa-f]+)$", std::regex::ECMAScript);
    if (!std::regex_match(m_old_hook, rx))
    {
        m_valid = false;
        return;
    }

    if (m_old_original.empty()) {
        m_valid = false;
        return;
    }

    if (!this->m_in_module && !std::regex_match(m_old_original, rx))
    {
        m_valid = false;
        return;
    }

    this->m_valid = true;
}


GuiSplugInlineHook::GuiSplugInlineHook(const YAML::Node& node) {
    if (!node.IsMap() && node.IsDefined() && !node.IsNull())
        throw runtime_error("GuiSplugInlineHook: node is not a map");

    this->m_enable = !node["disable"].as<bool>(false);

    auto add_module = [&](const YAML::Node& n, HookModule& hook_module) {
        auto& hooks = hook_module.m_hooks;
        hook_module.m_enable = !n["disable"].as<bool>(false);

        for (auto& pair : n) {
            bool enable = true;
            auto key = pair.first.as<string>();
            if (key == "disable")
                continue;

            auto hookval = pair.second;
            HookPairState state;
            state.m_enable = !hookval["disable"].as<bool>(false);
            state.m_remark = hookval["remark"].as<string>("");
            state.m_in_module = true;
            auto val = hookval["hook"].as<string>();
            strncpy(state.m_original.get(), key.c_str(), MAX_TARGET_LEN);
            strncpy(state.m_hook.get(),     val.c_str(), MAX_TARGET_LEN);
            hooks.push_back(state);
        }
    };

    for (auto& pair : node) {
        auto key = pair.first.as<string>();
        if (key == "disable")
            continue;

        auto& val = pair.second;
        const bool not_module = key.find("::") != string::npos || 
                                key.find('#') != string::npos || 
                                key.find('$') != string::npos;

        if (not_module) {
            auto mval = val["hook"].as<string>();
            HookPairState state;
            strncpy(state.m_original.get(), key.c_str(), MAX_TARGET_LEN);
            strncpy(state.m_hook.get(), mval.c_str(), MAX_TARGET_LEN);
            state.m_enable = !val["disable"].as<bool>(false);
            state.m_remark = val["remark"].as<string>("");
            this->m_hooks.push_back(state);
        } else {
            this->m_hooks_by_module[key] = HookModule();
            add_module(val, this->m_hooks_by_module[key]);
        }
    }
}

YAML::Node GuiSplugInlineHook::getNode() {
    YAML::Node node;
    node["disable"] = !this->m_enable;

    for (auto& pair : this->m_hooks_by_module) {
        YAML::Node n;
        n["disable"] = !pair.second.m_enable;

        for (auto& state : pair.second.m_hooks) {
            string org(state.m_original.get());
            if (!state.m_valid)
                continue;

            string trg(state.m_hook.get());
            YAML::Node trg_node;
            trg_node["disable"] = !state.m_enable;
            trg_node["hook"] = trg;
            trg_node["remark"] = state.m_remark;

            n[org] = trg_node;
        }
        node[pair.first] = n;
    }

    for (auto& state : this->m_hooks) {
        string org(state.m_original.get());
        if (!state.m_valid)
            continue;

        string trg(state.m_hook.get());
        YAML::Node trg_node;
        trg_node["disable"] = !state.m_enable;
        trg_node["hook"] = trg;
        trg_node["remark"] = state.m_remark;

        node[org] = trg_node;
    }

    return node;
}

static char new_module_name[MAX_TARGET_LEN];
bool GuiSplugInlineHook::show() {
    if (!this->visibility())
        return false;
    
    ImGui::Checkbox("启用", &this->m_enable);
    ImGui::Spacing();

    auto add_hook = [&](vector<HookPairState>& hooks, bool add_btn) {
        auto width = ImGui::GetWindowWidth();
        if (add_btn) {
            ImGui::SameLine();
            if (ImGui::Button("新增")) {
                HookPairState state;
                state.m_editing = true;
                state.m_in_module = true;
                hooks.push_back(state);
            }
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("新增一个函数 hook");

            ImGui::SameLine();
            if (ImGui::Button("删除")) {
                return false;
            }
            if (ImGui::IsItemHovered()) {
                ImGui::SetTooltip("删除此模块");
            }
        }

        vector<size_t> delete_s;
        ImVec2 mbtn_size(20, 20);
        if (hooks.size() > 0 && ImGui::BeginTable("##hook_table", 3)) {
            ImGui::TableSetupColumn("函数符号", ImGuiTableColumnFlags_WidthFixed, 0.4 * width);
            ImGui::TableSetupColumn("Hook 符号", ImGuiTableColumnFlags_WidthFixed, 0.4 * width);
            ImGui::TableSetupColumn("操作",  ImGuiTableColumnFlags_WidthFixed, 0.2 * width);
            ImGui::TableHeadersRow();

            size_t i = 0;
            for (auto it = hooks.begin(); it != hooks.end(); ++it, i++) {
                if (it->m_delete) {
                    delete_s.push_back(i);
                    continue;
                }

                ImGui::PushID(i);
                ImGui::TableNextRow();
                ImGui::TableNextColumn();

                it->revalidate();
                const bool is_valid = it->m_valid;
                if (!is_valid)
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.0f, 0.0f, 1.0f));

                if (it->m_editing && it->m_enable) {
                    ImGui::InputText("##origin", it->m_original.get(), MAX_TARGET_LEN);
                    ImGui::TableNextColumn();
                    ImGui::InputText("##hook", it->m_hook.get(), MAX_TARGET_LEN);
                } else {
                    ImGui::Text("%s", it->m_original.get());
                    if (ImGui::IsItemHovered()) {
                        ImGui::BeginTooltip();
                        ImGui::Text(it->m_original.get());
                        ImGui::EndTooltip();
                    }

                    ImGui::TableNextColumn();

                    ImGui::Text("%s", it->m_hook.get());
                    if (ImGui::IsItemHovered()) {
                        ImGui::BeginTooltip();
                        ImGui::Text(it->m_hook.get());
                        ImGui::EndTooltip();
                    }
                }
                if (!is_valid)
                    ImGui::PopStyleColor();

                ImGui::TableNextColumn();
                bool disabled = !it->m_enable;
                if (disabled)
                    ImGui::BeginDisabled();

                if (it->m_editing && it->m_enable) {
                    if (ImGui::Button("S", mbtn_size)) {
                        it->m_editing = false;
                    }
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("保存");
                } else {
                    if (ImGui::Button("E", mbtn_size)) {
                        it->m_editing = true;
                    }
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("编辑");
                }

                ImGui::SameLine();
                if (ImGui::Button("D", mbtn_size)) {
                    it->m_delete = true;
                }
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("删除");
                
                if (disabled)
                    ImGui::EndDisabled();
                
                ImGui::SameLine();
                ImGui::Checkbox("", &it->m_enable);

                if (!it->m_remark.empty()) {
                    ImGui::SameLine();
                    ImGui::Button(" ");
                    if (ImGui::IsItemHovered()) {
                        ImGui::BeginTooltip();
                        ImGui::Text(it->m_remark.c_str());
                        ImGui::EndTooltip();
                    }
                }

                ImGui::PopID();
            }
            ImGui::EndTable();
        }

        for (auto rit = delete_s.rbegin(); rit != delete_s.rend(); ++rit) {
            hooks.erase(hooks.begin() + *rit);
        }

        return true;
    };

    if (!this->m_hooks_by_module.empty()) {
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
    }

    vector<string> delete_m;
    for (auto& kv: this->m_hooks_by_module) {
        if (ImGui::TreeNode(kv.first.c_str())) {
            ImGui::PushID(kv.first.c_str());
            ImGui::Checkbox("启用", &kv.second.m_enable);
            bool disabled = !kv.second.m_enable;
            if (disabled)
                ImGui::BeginDisabled();

            if (!add_hook(kv.second.m_hooks, true)) {
                delete_m.push_back(kv.first);
            }
            if (disabled)
                ImGui::EndDisabled();
            ImGui::PopID();
            ImGui::TreePop();
        }
    }
    for (auto& d: delete_m) {
        this->m_hooks_by_module.erase(d);
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    if (!this->m_hooks.empty()) {
        ImGui::PushID("hooks");
        add_hook(this->m_hooks, false);
        ImGui::PopID();

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
    }

    auto width = ImGui::GetWindowWidth();
    ImVec2 space_size(width * 0.1, 20);
    ImVec2 btn_size((width - space_size.x * 3) / 2, 35);

    if (ImGui::BeginPopupModal("Add Module", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("##module", new_module_name, MAX_TARGET_LEN);

        if (ImGui::Button("新增")) {
            if (this->m_hooks_by_module.find(new_module_name) == this->m_hooks_by_module.end()) {
                HookModule nm;
                nm.m_enable = true;
                this->m_hooks_by_module[new_module_name] = nm;
            }
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("取消")) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
    ImGui::Dummy(space_size);
    ImGui::SameLine();
    if (ImGui::Button("新增模块", btn_size)) {
        ImGui::OpenPopup("Add Module");
    }
    ImGui::SameLine();
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("新增一个DLL模块");

    ImGui::SameLine();
    ImGui::Dummy(space_size);
    ImGui::SameLine();
    if (ImGui::Button("新增", btn_size)) {
        HookPairState state;
        state.m_editing = true;
        this->m_hooks.push_back(state);
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("新增一个 hook");

    return true;
}
