#include "scyllagui/widget/log_window.h"
#include <imgui.h>
using namespace std;


LogWindow::LogWindow(const std::string& window_title): m_window_title(window_title)
{
    this->visibility() = false;
    this->m_pagination.set_records(0);
}

void LogWindow::add_log(const std::string& log)
{
    lock_guard<std::recursive_mutex> lck(this->m_mutex);
    this->m_logs.push_back(log);
    this->m_pagination.set_records(this->m_logs.size());
}

void LogWindow::clear_log()
{
    lock_guard<std::recursive_mutex> lck(this->m_mutex);
    this->m_logs.clear();
    this->m_pagination.set_records(this->m_logs.size());
}

bool LogWindow::show()
{
    if (!this->visibility())
        return false;
    lock_guard<std::recursive_mutex> lck(this->m_mutex);

    size_t beg = this->m_pagination.record_begin();
    size_t end = this->m_pagination.record_end();

    if (ImGui::Begin(this->m_window_title.c_str(), &this->visibility(),
                     ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse))
    {
        auto win_size_y = ImGui::GetWindowHeight();
        auto textheight = ImGui::GetTextLineHeight();

        if (ImGui::BeginChild("Logs", ImVec2(0, win_size_y - textheight * 6.5), false)) {
            for (size_t i = beg; i < end; i++) {
                auto& log = this->m_logs[i];
                ImGui::Text("%s", log.c_str());
                ImGui::Separator();
                ImGui::Spacing();
            }

            ImGui::EndChild();
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        this->m_pagination.show();
        ImGui::SameLine();
        if (ImGui::Button("清空"))
            this->clear_log();

        ImGui::End();
    }
}
