#include "scyllagui/splug/iat_hook.h"
#include "scylla_constants.h"
#include "str_utils.h"
#include <stdexcept>
#include <regex>
#include <imgui.h>
using namespace std;

#define MAX_TARGET_LEN 1024

IATHookPairState::IATHookPairState()
{
    m_func_mem = shared_ptr<char>(new char[MAX_TARGET_LEN], std::default_delete<char[]>());
    m_target_mem = shared_ptr<char>(new char[MAX_TARGET_LEN], std::default_delete<char[]>());
    m_func_mem.get()[0] = '\0';
    m_target_mem.get()[0] = '\0';
    m_enable = true;
    m_valid = false;
    m_editing = false;
}

void IATHookPairState::revalidate() {
    if (_strnicmp(m_func_mem.get(), this->m_func.c_str(), MAX_TARGET_LEN) == 0 &&
        _strnicmp(m_target_mem.get(), this->m_target.c_str(), MAX_TARGET_LEN) == 0)
    {
        return;
    }

    this->m_func = m_func_mem.get();
    this->m_target = m_target_mem.get();

    static std::regex rx("^.+(::.+|\\$0x[0-9A-Fa-f]+|\\#0x[0-9A-Fa-f]+)$", std::regex::ECMAScript);
    if (!std::regex_match(this->m_target, rx))
    {
        m_valid = false;
        return;
    }

    if (m_func.empty()) {
        m_valid = false;
        return;
    }

    this->m_valid = true;
}


GuiSplugIATHook::GuiSplugIATHook(const YAML::Node& node) {
    if (!node.IsMap() && node.IsDefined() && !node.IsNull())
        throw runtime_error("GuiSplugIATHook: node is not a map");

    this->m_enable = !node["disable"].as<bool>(false);

    for (auto& pair : node) {
        auto key = pair.first.as<string>();
        if (key == "disable")
            continue;

        auto& modules = pair.second;
        if (!modules.IsMap() && !modules.IsNull())
            throw runtime_error("GuiSplugIATHook: module is not a map");
        
        IATHookModule ihmodule;
        ihmodule.m_enable = !modules["disable"].as<bool>(false);
        auto& imports = ihmodule.m_imports;
        for (auto& p2: modules) {
            auto importdll = p2.first.as<string>();
            if (importdll == "disable")
                continue;
            
            auto& functions = p2.second;
            if (!functions.IsMap() && !functions.IsNull())
                throw runtime_error("GuiSplugIATHook: import table is not a map");
            
            for (auto& p3: functions) {
                auto func = p3.first.as<string>();
                auto& target = p3.second;

                if (!target.IsMap() && !target.IsNull())
                    throw runtime_error("GuiSplugIATHook: target is not a map");
                
                auto hook = target["hook"].as<string>();
                IATHookPairState ihpair;
                ihpair.m_enable = !target["disable"].as<bool>(false);
                strncpy(ihpair.m_func_mem.get(), func.c_str(), MAX_TARGET_LEN);
                strncpy(ihpair.m_target_mem.get(), hook.c_str(), MAX_TARGET_LEN);
                ihpair.m_remark = target["remark"].as<string>("");
                ihpair.revalidate();
                imports[importdll].push_back(ihpair);
            }
        }

        this->m_modules[key] = ihmodule;
    }
}

YAML::Node GuiSplugIATHook::getNode() {
    YAML::Node node;
    node["disable"] = !this->m_enable;

    for (auto& p1: this->m_modules) {
        YAML::Node n2;
        n2["disable"] = !p1.second.m_enable;

        for (auto& p2: p1.second.m_imports) {
            YAML::Node n3;

            for (auto& p3: p2.second) {
                YAML::Node n4;

                n4["disable"] = !p3.m_enable;
                n4["remark"] = p3.m_remark;
                n4["hook"] = string(p3.m_target_mem.get());
                n3[string(p3.m_func_mem.get())] = n4;
            }
            n2[p2.first] = n3;
        }
        node[p1.first] = n2;
    }

    return node;
}

bool GuiSplugIATHook::show() {
    static char new_module_name[MAX_TARGET_LEN] = { 0 };
    static char new_module_import_name[MAX_TARGET_LEN] = { 0 };
    static string add_module_name;

    if (!this->visibility())
        return false;
    
    ImGui::Checkbox("启用", &this->m_enable);
    ImGui::Separator();
    ImGui::Spacing();

    set<string> delete_p1;
    for (auto& p1: this->m_modules) {
        auto& dllname = p1.first;
        auto& dllmodule = p1.second;

        ImGui::PushID(dllname.c_str());
        if (ImGui::TreeNode(dllname.c_str())) {
            ImGui::Checkbox("启用", &dllmodule.m_enable);
            ImGui::SameLine();
            if (ImGui::BeginPopupModal("Add DLL IMPORT", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
                ImGui::InputText("##dllmodule", new_module_import_name, MAX_TARGET_LEN);

                if (new_module_import_name[0] != '\0' && ImGui::Button("新增")) {
                    auto& ovov = this->m_modules.find(add_module_name);
                    if (ovov != this->m_modules.end()) {
                        auto& m = ovov->second;
                        if (m.m_imports.find(new_module_import_name) == m.m_imports.end())
                            m.m_imports[new_module_import_name] = vector<IATHookPairState>();
                        new_module_import_name[0] = '\0';
                    }
                    ImGui::CloseCurrentPopup();
                }
                ImGui::SameLine();
                if (ImGui::Button("取消")) {
                    ImGui::CloseCurrentPopup();
                }
                ImGui::EndPopup();
            }
            if (ImGui::Button("新增")) {
                add_module_name = dllname;
                ImGui::OpenPopup("Add DLL IMPORT");
            }
            ImGui::SameLine();
            if (ImGui::Button("删除"))
                delete_p1.insert(dllname);
            ImGui::Separator();
            ImGui::Spacing();

            set<string> delete_p2;
            for (auto& p2: dllmodule.m_imports) {
                auto& import_dll = p2.first;
                auto& functions = p2.second;

                auto sv = dllname + import_dll;
                ImGui::PushID(sv.c_str());
                if (ImGui::TreeNode(import_dll.c_str())) {
                    ImGui::Text("count = %d", functions.size());
                    ImGui::SameLine();
                    if (ImGui::Button("新增")) {
                        IATHookPairState newstate;
                        newstate.m_editing = true;
                        functions.push_back(newstate);
                    }
                    ImGui::SameLine();
                    if (ImGui::Button("删除"))
                        delete_p2.insert(import_dll);

                    if (functions.size() > 0 && ImGui::BeginTable("##iathook_table", 3)) {
                        auto width = ImGui::GetWindowWidth();
                        ImVec2 mbtn_size(20, 20);
                        ImGui::TableSetupColumn("函数符号", ImGuiTableColumnFlags_WidthFixed, 0.4 * width);
                        ImGui::TableSetupColumn("Hook 符号", ImGuiTableColumnFlags_WidthFixed, 0.4 * width);
                        ImGui::TableSetupColumn("操作",  ImGuiTableColumnFlags_WidthFixed, 0.2 * width);
                        ImGui::TableHeadersRow();

                        size_t i = 0;
                        set<size_t> delete_s;
                        for (auto it = functions.begin(); it != functions.end(); ++it, i++) {
                            ImGui::PushID(i);
                            ImGui::TableNextRow();
                            ImGui::TableNextColumn();

                            it->revalidate();
                            const bool is_valid = it->m_valid;
                            if (!is_valid)
                                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.0f, 0.0f, 1.0f));

                            if (it->m_editing && it->m_enable) {
                                ImGui::InputText("##func", it->m_func_mem.get(), MAX_TARGET_LEN);
                                ImGui::TableNextColumn();
                                ImGui::InputText("##hook", it->m_target_mem.get(), MAX_TARGET_LEN);
                            } else {
                                ImGui::Text("%s", it->m_func_mem.get());
                                if (ImGui::IsItemHovered()) {
                                    ImGui::BeginTooltip();
                                    ImGui::Text(it->m_func_mem.get());
                                    ImGui::EndTooltip();
                                }

                                ImGui::TableNextColumn();

                                ImGui::Text("%s", it->m_target_mem.get());
                                if (ImGui::IsItemHovered()) {
                                    ImGui::BeginTooltip();
                                    ImGui::Text(it->m_target_mem.get());
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
                                delete_s.insert(i);
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

                        for (auto l=delete_s.rbegin(); l!=delete_s.rend(); ++l) {
                            auto v = functions.begin() + *l;
                            functions.erase(v);
                        }

                        ImGui::EndTable();
                    }
                    ImGui::TreePop();
                }
                ImGui::PopID();
            }
            for (auto& d2: delete_p2)
                dllmodule.m_imports.erase(d2);

            ImGui::TreePop();
        }
        ImGui::PopID();
    }
    for (auto& d1: delete_p1)
        this->m_modules.erase(d1);

    auto width = ImGui::GetWindowWidth();
    ImVec2 space_size(width * 0.1, 20);
    ImVec2 btn_size((width - space_size.x * 2), 25);

    if (ImGui::BeginPopupModal("Add IAT Module", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::InputText("##module", new_module_name, MAX_TARGET_LEN);

        if (new_module_name[0] != '\0' && ImGui::Button("新增")) {
            if (this->m_modules.find(new_module_name) == this->m_modules.end()) {
                IATHookModule nm;
                nm.m_enable = true;
                this->m_modules[new_module_name] = nm;
            }
            new_module_name[0] = '\0';
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("取消")) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Dummy(space_size);
    ImGui::SameLine();
    if (ImGui::Button("新增模块", btn_size)) {
        ImGui::OpenPopup("Add IAT Module");
    }
    ImGui::SameLine();
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("新增一个DLL模块");

    return true;
}
