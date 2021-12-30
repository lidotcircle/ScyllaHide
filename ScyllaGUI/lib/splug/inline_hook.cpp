#include "scyllagui/splug/inline_hook.h"
#include "scylla_constants.h"
#include "str_utils.h"
#include <stdexcept>
#include <imgui.h>
using namespace std;

#define MAX_TARGET_LEN 1024


GuiSplugInlineHook::GuiSplugInlineHook(const YAML::Node& node) {
    if (!node.IsMap() && node.IsDefined())
        throw runtime_error("GuiSplugInlineHook: node is not a map");

    this->m_enable = !node["disable"].as<bool>(false);

    auto add_module = [&](const YAML::Node& n, HookModule& hook_module) {
        auto& hooks = hook_module.m_hooks;
        hook_module.m_enable = true;
        if (n.IsMap())
            hook_module.m_enable = !n["disable"].as<bool>(false);

        for (auto& pair : n) {
            bool enable = true;
            auto key = pair.first.as<string>();
            if (key == "disable")
                continue;

            auto val = trimstring(pair.second.as<string>());
            if (val.find(INLINE_HOOK_DISABLE_PREFIX) == 0) {
                enable = false;
                val = val.substr(strlen(INLINE_HOOK_DISABLE_PREFIX));
                val = trimstring(val);
            }
            string remark;
            if (val.find(INLINE_HOOK_REMARK_SEPARATOR) != string::npos) {
                remark = val.substr(val.find(INLINE_HOOK_REMARK_SEPARATOR) + strlen(INLINE_HOOK_REMARK_SEPARATOR));
                val = val.substr(0, val.find(INLINE_HOOK_REMARK_SEPARATOR));
            }
            auto s_key = shared_ptr<char>(new char[MAX_TARGET_LEN], std::default_delete<char[]>());
            auto s_val = shared_ptr<char>(new char[MAX_TARGET_LEN], std::default_delete<char[]>());
            strncpy(s_key.get(), key.c_str(), MAX_TARGET_LEN);
            strncpy(s_val.get(), val.c_str(), MAX_TARGET_LEN);
            HookPairState state;
            state.m_enable = enable;
            state.m_original = s_key;
            state.m_hook = s_val;
            state.m_remark = remark;
            state.m_editing = false;
            state.m_delete = false;
            hooks.push_back(state);
        }
    };

    for (auto& pair : node) {
        auto key = pair.first.as<string>();
        auto val = pair.second;

        if (key == "disable")
            continue;

        if (val.IsMap()) {
            this->m_hooks_by_module[key] = HookModule();
            add_module(val, this->m_hooks_by_module[key]);
        } else {
            auto mval = val.as<string>();
            auto s_key = shared_ptr<char>(new char[MAX_TARGET_LEN], std::default_delete<char[]>());
            auto s_val = shared_ptr<char>(new char[MAX_TARGET_LEN], std::default_delete<char[]>());
            strncpy(s_key.get(), key.c_str(), MAX_TARGET_LEN);
            strncpy(s_val.get(), mval.c_str(), MAX_TARGET_LEN);
            HookPairState state;
            state.m_original = s_key;
            state.m_hook = s_val;
            state.m_editing = false;
            state.m_delete = false;
            this->m_hooks.push_back(state);
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
            string trg(state.m_hook.get());

            if (org.empty())
                continue;

            if (!state.m_enable)
                trg = INLINE_HOOK_DISABLE_PREFIX + trg;
            
            if (!state.m_remark.empty())
                trg += INLINE_HOOK_REMARK_SEPARATOR + state.m_remark;

            n[org] = trg;
        }
        node[pair.first] = n;
    }

    for (auto& state : this->m_hooks) {
        string org(state.m_original.get());
        string trg(state.m_hook.get());

        if (org.empty())
            continue;

        if (!state.m_enable)
            trg = INLINE_HOOK_DISABLE_PREFIX + trg;
        
        if (!state.m_remark.empty())
            trg += INLINE_HOOK_REMARK_SEPARATOR + state.m_remark;

        node[org] = trg;
    }

    return node;
}

static char new_module_name[MAX_TARGET_LEN];
bool GuiSplugInlineHook::show() {
    if (!this->visibility())
        return false;
    
    ImGui::Checkbox("Enable", &this->m_enable);
    ImGui::Spacing();

    auto add_hook = [&](vector<HookPairState>& hooks, bool add_btn) {
        auto width = ImGui::GetWindowWidth();
        vector<size_t> delete_s;
        ImVec2 mbtn_size(20, 20);
        if (hooks.size() > 0 && ImGui::BeginTable("##hook_table", 3)) {
            ImGui::TableSetupColumn("Original", ImGuiTableColumnFlags_WidthFixed, 0.4 * width);
            ImGui::TableSetupColumn("Hook", ImGuiTableColumnFlags_WidthFixed, 0.4 * width);
            ImGui::TableSetupColumn("Actions",  ImGuiTableColumnFlags_WidthFixed, 0.2 * width);
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

        if (!add_btn)
            return true;

        ImVec2 space_size(width * 0.1, 20);
        ImVec2 btn_size((width - space_size.x * 3) / 2, 35);
        ImGui::Dummy(space_size);
        ImGui::SameLine();
        if (ImGui::Button("Add", btn_size)) {
            HookPairState state;
            state.m_delete = false;
            state.m_editing = true;
            state.m_original = shared_ptr<char>(new char[MAX_TARGET_LEN], std::default_delete<char[]>());
            state.m_original.get()[0] = '\0';
            state.m_hook = shared_ptr<char>(new char[MAX_TARGET_LEN], std::default_delete<char[]>());
            state.m_hook.get()[0] = '\0';
            hooks.push_back(state);
        }
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("新增一个函数 hook");
        ImGui::SameLine();
        ImGui::Dummy(space_size);
        ImGui::SameLine();

        if (ImGui::Button("Delete", btn_size)) {
            return false;
        }
        if (ImGui::IsItemHovered()) {
            ImGui::SetTooltip("删除此模块");
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
            ImGui::Checkbox("enable", &kv.second.m_enable);
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

        if (ImGui::Button("Add")) {
            if (this->m_hooks_by_module.find(new_module_name) == this->m_hooks_by_module.end()) {
                HookModule nm;
                nm.m_enable = true;
                this->m_hooks_by_module[new_module_name] = nm;
            }
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel")) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
    ImGui::Dummy(space_size);
    ImGui::SameLine();
    if (ImGui::Button("Add Module", btn_size)) {
        ImGui::OpenPopup("Add Module");
    }
    ImGui::SameLine();
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("新增一个模块");

    ImGui::SameLine();
    ImGui::Dummy(space_size);
    ImGui::SameLine();
    if (ImGui::Button("Add", btn_size)) {
        HookPairState state;
        state.m_delete = false;
        state.m_editing = true;
        state.m_original = shared_ptr<char>(new char[MAX_TARGET_LEN], std::default_delete<char[]>());
        state.m_original.get()[0] = '\0';
        state.m_hook = shared_ptr<char>(new char[MAX_TARGET_LEN], std::default_delete<char[]>());
        state.m_hook.get()[0] = '\0';
        this->m_hooks.push_back(state);
    }
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("新增一个 hook");

    return true;
}
