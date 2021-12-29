#include <stdio.h>
#include <Windows.h>
#include "imgui.h"
#include "scyllagui/imgui_app.h"
#include "scyllagui/splug/splug_view.h"
#include "scylla/utils.h"
#include "scylla/charybdis.h"
#include <fstream>
#include <sstream>
#include <string>
using namespace std;

#define MAX_CMDLINE_ARGS_LEN 1024


class ScyllaAPP: public ImGuiAPP
{
private:
    unique_ptr<GuiSplugView> m_splugView;
    string m_fileName;

    enum RunningMode {
        RunningMode_CMDLine = 0,
        RunningMode_ProcessName,
        RunningMode_PID,
    } m_mode;

    vector<string> m_logs;
    bool m_recieve_log;
    bool m_show_log_window;

    std::shared_ptr<char> m_executable;
    std::shared_ptr<char> m_cmdline;
    std::shared_ptr<char> m_process_name;
    bool m_pid_resolved_by_process_name;
    int m_pid;
    int m_prev_pid;
    string process_name_by_pid;

    bool m_injected;
    int  m_injected_pid;
    shared_ptr<WinProcessNative> m_process;
    unique_ptr<scylla::Charybdis> m_charybdis;

    void child_window_control();
    void new_process_widget();
    void process_name_widget();
    void process_id_widget();

    void log_window();

    bool inject_process();
    void undo_inject();

protected:
    virtual int render_frame() override;

public:
    ScyllaAPP(): ImGuiAPP("Scylla Monitor", 500, 700) {
        if (ifstream("scylla.yaml")) {
            m_fileName = "scylla.yaml";
        }

        this->m_mode = RunningMode_CMDLine;
        m_executable = shared_ptr<char>(new char[MAX_PATH], std::default_delete<char[]>());
        m_executable.get()[0] = '\0';
        m_cmdline = shared_ptr<char>(new char[MAX_CMDLINE_ARGS_LEN], std::default_delete<char[]>());
        m_cmdline.get()[0] = '\0';
        m_process_name = shared_ptr<char>(new char[MAX_PATH], std::default_delete<char[]>());
        m_process_name.get()[0] = '\0';
        this->m_pid = 0;
 
        this->m_recieve_log = true;
        this->m_show_log_window = false;

        this->m_injected = false;
        this->m_injected_pid = 0;

        try {
            YAML::Node node;
            if (!m_fileName.empty())
                node = YAML::LoadFile(m_fileName);
            this->m_splugView = make_unique<GuiSplugView>(node);
        } catch (exception& e) {
            MessageBox(NULL, e.what(), "Error", MB_OK);
        }
    }

    void openFile(const string& filename) {
        try {
            auto node = YAML::LoadFile(filename);
            this->m_splugView = make_unique<GuiSplugView>(node);
            this->m_fileName = filename;
        } catch (exception& e) {
            MessageBox(NULL, e.what(), "Error", MB_OK);
        }
    }

    string dump() {
        stringstream ss;
        auto node = this->m_splugView->getNode();
        ss << node;
        return ss.str();
    }

    void saveFile(const string& filename) {
        ofstream outfile(filename);
        if (!outfile.is_open()) {
            string err ="Failed to open file '" + filename + "'";
            MessageBoxA(NULL, err.c_str(), "Error", MB_OK);
            return;
        }

        outfile << this->m_splugView->getNode();
        this->m_fileName = filename;
    }

    void saveFile() {
        if (this->m_fileName.empty())
            throw runtime_error("No file to save");
        this->saveFile(this->m_fileName);
    }
};

int ScyllaAPP::render_frame() {
    auto& io = ImGui::GetIO();
    ImGui::SetNextWindowPos( ImVec2(0,0) );
    ImGui::SetNextWindowSize(ImVec2(io.DisplaySize.x, io.DisplaySize.y));

    if (ImGui::Begin("MainWindow" , nullptr , 
                 ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
                 ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings | 
                 ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoScrollbar | 
                 ImGuiWindowFlags_NoScrollWithMouse |
                 ImGuiWindowFlags_NoBringToFrontOnFocus))
    {
        if (ImGui::BeginChild("FileMenu", ImVec2(0, 20), false, ImGuiWindowFlags_NoScrollbar))
        {
            if (ImGui::Button("Open")) {
                auto file = ChooserFile("YAML (*.yaml)\0*.yaml\0ALL Files (*.*)\0*.*\0");
                if (file != nullptr)
                    this->openFile(file);
            }
            ImGui::SameLine();
            if (ImGui::Button("Save")) {
                if (!this->m_fileName.empty()) {
                    this->saveFile();
                } else {
                    auto file = SaveFileTo("YAML (*.yaml)\0*.yaml\0ALL Files (*.*)\0*.*\0", "scylla.yaml");
                    if (file != nullptr)
                        this->saveFile(file);
                }
            }
            ImGui::SameLine();
            if (ImGui::Button("Save As")) {
                auto file = SaveFileTo("YAML (*.yaml)\0*.yaml\0ALL Files (*.*)\0*.*\0", "scylla.yaml");
                if (file != nullptr)
                    this->saveFile(file);
            }
            ImGui::EndChild();
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        ImGui::Spacing();

        auto h = ImGui::GetWindowHeight();
        if (h > (175 + 30)) {
            h -= (175 + 30);
        } else {
            h = 30;
        }
        if (ImGui::BeginChild("config", ImVec2(0, h), false)) {
            this->m_splugView->show();
            ImGui::EndChild();
        }

        ImGui::Spacing();
        if (ImGui::BeginChild("control", ImVec2(0, 0), true)) {
            this->child_window_control();
            ImGui::EndChild();
        }

       this->log_window();
        
        ImGui::End();
    }

    return 0;
}

void ScyllaAPP::child_window_control()
{
    static const char* modes[] = {
        "By Command Line",
        "By Process Name",
        "By Process ID"
    };

    if (ImGui::BeginCombo("Running Mode", modes[m_mode])) {
        for (int i = 0; i < 3; i++) {
            const bool is_selected = (i == m_mode);
            if (ImGui::Selectable(modes[i], is_selected)) {
                m_mode = static_cast<RunningMode>(i);
            }
            if (is_selected)
                ImGui::SetItemDefaultFocus();
        }
        ImGui::EndCombo();
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    switch (m_mode)
    {
    case RunningMode_CMDLine:
        this->new_process_widget();
        break;
    case RunningMode_ProcessName:
        this->process_name_widget();
        break;
    case RunningMode_PID:
        this->process_id_widget();
        break;
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    if (ImGui::Button("Start")) {
        this->m_injected = this->inject_process();
    }

    if (!this->m_injected)
        ImGui::BeginDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Undo")) {
        this->undo_inject();
    }
    if (!this->m_injected)
        ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::Checkbox("Show Log Window", &m_show_log_window);

    ImGui::SameLine();
    ImGui::Checkbox("Recieve Log", &m_recieve_log);
}

void ScyllaAPP::new_process_widget() {
    ImGui::InputText("Executable", m_executable.get(), MAX_PATH);
    ImGui::SameLine();
    if (ImGui::Button("...")) {
        auto file = ChooserFile("Executable (*.exe)\0*.exe\0ALL Files (*.*)\0*.*\0");
        if (file != nullptr)
            strncpy(m_executable.get(), file, MAX_PATH);
    }

    ImGui::InputText("CMDLine Arguments", m_cmdline.get(), MAX_CMDLINE_ARGS_LEN);
}
void ScyllaAPP::process_name_widget() {
    ImGui::InputText("Process Name", m_process_name.get(), MAX_PATH);

    if (ImGui::Button("R")) {
        string pn(m_process_name.get());
        auto pid = GetPidByProcessName(pn);

        if (pid > 0) {
            this->m_pid_resolved_by_process_name = true;
            this->m_pid = pid;
        }
    }

    if (this->m_pid_resolved_by_process_name) {
        ImGui::SameLine();
        ImGui::Text("PID: %d", this->m_pid);
    }
}
void ScyllaAPP::process_id_widget() {
    ImGui::InputInt("Process ID", &this->m_pid);

    if (this->m_pid < 0)
        this->m_pid = 0;

    if (ImGui::Button("R") && this->m_pid > 0) {
        auto pn = GetProcessNameByPid(this->m_pid);
        if (pn != nullptr) {
            this->process_name_by_pid = pn;
            this->m_prev_pid = this->m_pid;
        }
    }

    if (this->m_prev_pid == this->m_pid && !this->process_name_by_pid.empty()) {
        ImGui::SameLine();
        ImGui::Text(this->process_name_by_pid.c_str());
    }
}

void ScyllaAPP::log_window() {
    if (!this->m_show_log_window)
        return;
    
    if (ImGui::Begin("Log", &this->m_show_log_window)) {
        for (auto& log : this->m_logs) {
            ImGui::Text(log.c_str());
            ImGui::Separator();
            ImGui::Spacing();
        }
    }
}

bool ScyllaAPP::inject_process() {
    return false;
}

void ScyllaAPP::undo_inject() {
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    ScyllaAPP app;

    app.run_loop();
    return 0;
}
