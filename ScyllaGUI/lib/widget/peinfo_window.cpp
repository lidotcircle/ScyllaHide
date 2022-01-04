#include "scyllagui/widget/peinfo_window.h"
#include "str_utils.h"
#include <imgui.h>
using namespace std;


PEInfoWindow::PEInfoWindow()
{
    this->visibility() = false;
}

PEInfoWindow::PEInfoWindow(std::string modname, shared_ptr<MemoryMapPEFile> pefile):
    m_modulename(modname), m_pefile(pefile)
{
    this->m_title = "PE Info - " + this->m_modulename;

    auto& _exports = pefile->exports();
    for (auto& e: _exports)
        this->m_exports.push_back(e.second.first);

    this->visibility() = false;
}

bool PEInfoWindow::show() {
    if (!this->visibility())
        return false;
    
    if (ImGui::Begin(this->m_title.c_str(), &this->visibility())) {
        if (ImGui::CollapsingHeader("导出符号")) {
            if (ImGui::BeginTable("##export_table", 2)) {
                ImGui::TableSetupColumn("符号名");
                ImGui::TableSetupColumn("操作", ImGuiTableColumnFlags_WidthFixed, 50);
                ImGui::TableHeadersRow();

                for (size_t i=0;i<this->m_exports.size();i++) {
                    ImGui::PushID(i);
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::Text(this->m_exports[i].c_str());
                    ImGui::TableNextColumn();
                    if (ImGui::Button("复制")) {
                        string str = this->m_modulename + "::" + this->m_exports[i];
                        ImGui::SetClipboardText(str.c_str());
                    }

                    ImGui::PopID();
                }

                ImGui::EndTable();
            }
        }
        
        ImGui::End();
    }
}