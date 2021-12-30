#include <stdio.h>
#include <Windows.h>
#include "imgui.h"
#include "scyllagui/imgui_app.h"
#include "scyllagui/splug/splug_view.h"
#include "scylla/splug/log_server.h"
#include "scylla/utils.h"
#include "scylla/charybdis.h"
#include "logger/log_client.h"
#include <chrono>
#include <fstream>
#include <sstream>
#include <string>
using namespace std;

#define MAX_CMDLINE_ARGS_LEN 1024


class ScyllaAPP: public ImGuiAPP, protected LogClient
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

    string m_log_msg;
    std::chrono::system_clock::time_point m_log_prev_timestamp;
    enum {
        Log_None,
        Log_Info,
        Log_Warning,
        Log_Error,
    } m_log_level;

    void child_window_control();
    void new_process_widget();
    void process_name_widget();
    void process_id_widget();

    void log_window();

    bool inject_process();
    void undo_inject();

    void log_display_line();

protected:
    virtual int render_frame() override;
    virtual void send(const char* buf, uint16_t bufsize) override;
    void info(const char* fmt, ...);
    void warn(const char* fmt, ...);
    void error(const char* fmt, ...);

public:
    ScyllaAPP(): ImGuiAPP("Scylla Monitor", 500, 700) {
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

        if (ifstream("scylla.yaml")) {
            m_fileName = "scylla.yaml";
            this->openFile(this->m_fileName);
        }
    }

    void openFile(const string& filename) {
        try {
            auto node = YAML::LoadFile(filename);
            this->m_splugView = make_unique<GuiSplugView>(node);
            this->m_fileName = filename;
            this->info("Loaded file: %s", filename.c_str());
        } catch (exception& e) {
            this->error("Load config failed: %s", e.what());
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
            this->error("Failed to open file %s", filename.c_str());
            return;
        }

        outfile << this->m_splugView->getNode();
        this->m_fileName = filename;
        this->info("Saved to '%s'", filename.c_str());
    }

    void saveFile() {
        if (this->m_fileName.empty())
            this->warn("No file name specified");

        this->saveFile(this->m_fileName);
    }
};

int ScyllaAPP::render_frame() {
    auto& io = ImGui::GetIO();
    auto viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowViewport(viewport->ID);
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);

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
        if (h > (210 + 30)) {
            h -= (210 + 30);
        } else {
            h = 30;
        }
        if (ImGui::BeginChild("config", ImVec2(0, h), false)) {
            this->m_splugView->show();
            ImGui::EndChild();
        }

        this->log_display_line();

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
        } else {
            this->warn("Process ID %d not found", this->m_pid);
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
    WinProcessNative::suspend_t suspend_state;

    if (this->m_mode == RunningMode_CMDLine) {
        string _exe(m_executable.get());
        string _cmdline(m_cmdline.get());
        suspend_state = CreateProcessAndSuspend(_exe + " " + _cmdline, this->m_process, SUSPEND_ON_ENTRYPOINT);

        if (!suspend_state) {
            this->warn("Failed to create process and suspend it");
            return false;
        }
    } else if (this->m_mode == RunningMode_ProcessName) {
        this->m_pid = GetPidByProcessName(this->m_process_name.get());

        if (this->m_pid == 0) {
            this->warn("Process %s not found", this->m_process_name.get());
            return false;
        }
    } else if (this->m_mode == RunningMode_PID) {
        try {
            this->m_process = make_shared<WinProcessNative>(this->m_pid);
        } catch (const std::exception& e) {
            this->warn("inject into '%d' failed: %s", this->m_pid, e.what());
            return false;
        }
    } else {
        this->error("Unknown running mode");
        return false;
    }

    if (!suspend_state) {
        suspend_state = this->m_process->suspendThread();
        if (!suspend_state) {
            this->warn("Failed to suspend process");
            return false;
        }
    }

    auto log_server_config = make_shared<scylla::LogServerConfig>();
    log_server_config->data = this;
    log_server_config->is_callback_log_server = true;
    log_server_config->on_log = [](const char* log, int len, void* data) {
        auto self = static_cast<ScyllaAPP*>(data);
        if (!self->m_recieve_log)
            return;
        self->m_logs.push_back(string(log, len));
    };

    try {
        this->m_charybdis = make_unique<scylla::Charybdis>(this->m_process);
        auto config = this->m_charybdis->get_splug_config();
        config->set("logger", log_server_config);

        this->m_charybdis->doit(this->m_splugView->getNode());
        this->m_injected = true;
        if (!this->m_process->resumeThread(std::move(suspend_state))) {
            this->warn("Failed to resume process");
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        this->warn("Failed to create Charybdis: %s", e.what());
        return false;
    }
}

void ScyllaAPP::undo_inject() {
    if (!this->m_injected) {
        this->error("Nothing to undo, this should never happen");
        return;
    }

    if (!this->m_charybdis) {
        this->error("Charybdis is nullptr, this should never happen");
        return;
    }

    try {
        this->m_charybdis->undo();
        this->m_injected = false;
    } catch (const std::exception& e) {
        this->error("Failed to undo: %s", e.what());
    }
}

void ScyllaAPP::send(const char* msg, uint16_t len) {
    this->m_log_msg = string(msg, len);
    this->m_log_prev_timestamp = std::chrono::system_clock::now();
}

void ScyllaAPP::info(const char* msg, ...) {
    this->m_log_level = Log_Info;
    va_list args;
    va_start(args, msg);
    this->send_var("", msg, args);
    va_end(args);
}
void ScyllaAPP::warn(const char* msg, ...) {
    this->m_log_level = Log_Warning;
    va_list args;
    va_start(args, msg);
    this->send_var("", msg, args);
    va_end(args);
}
void ScyllaAPP::error(const char* msg, ...) {
    this->m_log_level = Log_Error;
    va_list args;
    va_start(args, msg);
    this->send_var("", msg, args);
    va_end(args);
}

void ScyllaAPP::log_display_line() {
    auto now = std::chrono::system_clock::now();
    auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(now - this->m_log_prev_timestamp).count();
    if (diff > 5000) {
        ImGui::Spacing();
        ImGui::Spacing();
        ImGui::Text("");
    } else {
        ImGui::Separator();
        ImGui::Spacing();

        bool need_pop_color = true;
        if (this->m_log_level == Log_Info) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.0f, 1.0f, 0.0f, 1.0f));
        } else if (this->m_log_level == Log_Warning) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 0.0f, 1.0f));
        } else if (this->m_log_level == Log_Error) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.0f, 0.0f, 1.0f));
        } else {
            need_pop_color = false;
        }
        ImGui::Text(this->m_log_msg.c_str());
        if (need_pop_color)
            ImGui::PopStyleColor();
    }
    ImGui::Spacing();
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    ScyllaAPP app;

    app.run_loop();
    return 0;
}
