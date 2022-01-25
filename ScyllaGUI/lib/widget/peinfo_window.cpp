#include "scyllagui/widget/peinfo_window.h"
#include "str_utils.h"
#include <imgui.h>
using namespace std;
using addr_t = MapPEModule::addr_t;


PEInfoWindow::PEInfoWindow()
{
    this->visibility() = false;
}

PEInfoWindow::PEInfoWindow(std::string modname, shared_ptr<MemoryMapPEFile> pefile):
    m_modulename(modname), m_pefile(pefile)
{
    this->m_title = "PE Info - " + this->m_modulename;

    this->visibility() = false;
}

bool PEInfoWindow::show() {
    if (!this->visibility())
        return false;
   
    if (ImGui::Begin(this->m_title.c_str(), &this->visibility())) {
        this->show_basic_info();
        this->show_exports();
        this->show_imports();
        ImGui::End();
    }
}

void PEInfoWindow::show_basic_info() const
{
#ifdef _WIN64
    ImGui::Text("Prefered Image Base: 0x%016x", this->m_pefile->header().imageBase());
#else
    ImGui::Text("Prefered Image Base: 0x%08x", this->m_pefile->header().imageBase());
#endif
}

void PEInfoWindow::show_exports() const
{
    auto& exports = this->m_pefile->exports();

    if (ImGui::CollapsingHeader("导出符号")) {
        ImGui::Text("exports (%d):", exports.size());

        if (ImGui::BeginTable("##export_table", 3)) {
            ImGui::TableSetupColumn("符号名");
            ImGui::TableSetupColumn("RVA");
            ImGui::TableSetupColumn("操作", ImGuiTableColumnFlags_WidthFixed, 50);
            ImGui::TableHeadersRow();

            size_t i = 0;
            for (auto it = exports.begin(); it != exports.end(); ++it, ++i) {
                auto& kv = it->second;
                ImGui::PushID(i);
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text(kv.first.c_str());

                ImGui::TableNextColumn();
#ifdef _WIN64
                ImGui::Text("0x%016X", kv.second);
#else
                ImGui::Text("0x%08X", kv.second);
#endif

                ImGui::TableNextColumn();
                if (ImGui::Button("复制")) {
                    string str = this->m_modulename + "::" + kv.first;
                    ImGui::SetClipboardText(str.c_str());
                }

                ImGui::PopID();
            }

            ImGui::EndTable();
        }
    }
}

void PEInfoWindow::show_imports() const
{
    auto& imports = this->m_pefile->imports();

    if (ImGui::CollapsingHeader("导入符号")) {
        for (auto& dll_imports: imports) {
            auto& dll_name = dll_imports.first;
            auto& imports = dll_imports.second;
            const auto treenode_name = dll_name + " (" + to_string(imports.size()) + ")";

            if (ImGui::TreeNode(treenode_name.c_str())) {
                if (ImGui::BeginTable("##import_table", 3)) {
                    ImGui::TableSetupColumn("符号名");
                    ImGui::TableSetupColumn("IAT Entry");
                    ImGui::TableSetupColumn("操作", ImGuiTableColumnFlags_WidthFixed, 50);
                    ImGui::TableHeadersRow();

                    size_t i = 0;
                    for (auto it = imports.begin(); it != imports.end(); ++it, ++i) {
                        auto& entry = it->first;
                        auto  addr = it->second;
                        auto& kv = it->second;
                        ImGui::PushID(i);
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn();
                        if (entry.is_ordinal()) {
                            ImGui::Text("%d", entry.ordinal());
                        } else {
                            ImGui::Text("%s", entry.symbolname().c_str());
                        }

                        ImGui::TableNextColumn();
#ifdef _WIN64
                        ImGui::Text("0x%016X", addr);
#else
                        ImGui::Text("0x%08X", addr);
#endif

                        ImGui::TableNextColumn();
                        if (ImGui::Button("复制")) {
                            const auto is_ordinal = entry.is_ordinal();
                            string str;
                            if (!is_ordinal) {
                                str = dll_name + "::" + entry.symbolname();
                            } else {
                                // TODO
                                str = dll_name + "$" + std::to_string(addr);
                            }

                            ImGui::SetClipboardText(str.c_str());
                        }

                        ImGui::PopID();
                    }

                    ImGui::EndTable();
                }
            }
        }
    }
}