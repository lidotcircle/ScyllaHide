#include "scyllagui/widget/process_select_window.h"
#include "scylla/utils.h"
#include <imgui.h>
using namespace std;


ProcessSelectWindow::ProcessSelectWindow() {}

void ProcessSelectWindow::refresh_processes()
{
    auto list = GetProcessList();
    this->m_processes.clear();
    for (auto& ps: list) {
        auto pid = ps.th32ProcessID;
        string pn(ps.szExeFile);
        if (pn.find("\\") != string::npos)
            pn = pn.substr(pn.find_last_of("\\") + 1);

        ProcessState pcs;
        pcs.m_name = pn;
        pcs.m_pid = pid;
        pcs.m_pid_str = to_string(pid);
        this->m_processes.push_back(pcs);
    }

    this->m_selected.m_pid = 0;
    this->visibility() = true;
}

const ProcessSelectWindow::ProcessState& ProcessSelectWindow::get_selected() const {
    return this->m_selected;
}

ProcessSelectWindow::ProcessState& ProcessSelectWindow::get_selected() {
    return this->m_selected;
}

bool ProcessSelectWindow::show()
{
    if (!this->visibility())
        return false;
    
    bool not_selected = true;
    if (ImGui::BeginPopupModal("Process Select", &this->visibility())) {
        if (ImGui::BeginTable("##process_table", 3)) {
            ImGui::TableSetupColumn("名称");
            ImGui::TableSetupColumn("进程ID", ImGuiTableColumnFlags_WidthFixed, 100);
            ImGui::TableSetupColumn("操作", ImGuiTableColumnFlags_WidthFixed, 50);
            ImGui::TableHeadersRow();

            size_t i = 0;
            for (auto it = this->m_processes.begin(); it != this->m_processes.end(); ++it, i++) {
                ImGui::PushID(i);
                ImGui::TableNextRow();
                ImGui::TableNextColumn();

                ImGui::Text("%s", it->m_name.c_str());
            
                ImGui::TableNextColumn();
                ImGui::Text("%s", it->m_pid_str.c_str());

                ImGui::TableNextColumn();
                if (ImGui::Button("选择")) {
                    this->m_selected = *it;
                    not_selected = false;
                }
 
                ImGui::PopID();
            }
            ImGui::EndTable();
        }

        ImGui::EndPopup();
    }

    ImGui::OpenPopup("Process Select");
    return not_selected;
}
