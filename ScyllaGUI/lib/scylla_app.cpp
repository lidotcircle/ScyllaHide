#include "scyllagui/scylla_app.h"
#include "scylla/splug/log_server.h"
#include "logger/log_client_callback.h"
#include <imgui.h>
#include <fstream>
#include <sstream>
using namespace std;

#define MAX_CMDLINE_ARGS_LEN 1024


ScyllaGuiApp::ScyllaGuiApp(bool dbgplugin_mode):
    ImGuiAPP("Scylla Monitor", 500, 700),
    m_remote_log_window("Remote Log Window"),
    m_local_log_window("Local Log Window"), m_local_logger(nullptr),
    m_dbgplugin_mode(dbgplugin_mode)
{
    this->m_mode = RunningMode_CMDLine;
    if (dbgplugin_mode)
        this->m_mode = RunningMode_PID;

    m_executable = shared_ptr<char>(new char[MAX_PATH], std::default_delete<char[]>());
    m_executable.get()[0] = '\0';
    m_cmdline = shared_ptr<char>(new char[MAX_CMDLINE_ARGS_LEN], std::default_delete<char[]>());
    m_cmdline.get()[0] = '\0';
    m_process_name = shared_ptr<char>(new char[MAX_PATH], std::default_delete<char[]>());
    m_process_name.get()[0] = '\0';
    this->m_pid = 0;

    this->m_wait_for_process_select = false;

    this->m_receive_remote_log = true;
    this->m_local_logger = make_shared<LogClientCallback>(
        [](const char* buf, uint16_t bufsize, void* data) {
            auto self = static_cast<ScyllaGuiApp*>(data);
            self->send(buf, bufsize);
        }, this);

    this->m_suspending_state_index = 0;
    this->m_suspending_state = SuspendingState::SUSPEND_ON_NO_SUSPEND;

    this->m_injected = false;
    this->m_injected_pid = 0;

    try {
        YAML::Node empty;
        this->m_splug_view = make_unique<GuiSplugView>(empty, m_dbgplugin_mode);
    } catch (exception& e) {
        this->error(e.what());
    }

    if (ifstream("scylla.yaml")) {
        m_config_file = "scylla.yaml";
        this->open_file(this->m_config_file);
    }
}

void ScyllaGuiApp::open_file(const string& filename)
{
    try {
        char fullfilename[MAX_PATH];
        auto n = GetFullPathNameA(filename.c_str(), MAX_PATH, fullfilename, nullptr);
        if (n == 0 || n > MAX_PATH)
            throw runtime_error("GetFullPathNameA failed");

        auto node = YAML::LoadFile(fullfilename);
        this->m_splug_view = make_unique<GuiSplugView>(node, m_dbgplugin_mode);
        this->m_config_file = fullfilename;
        this->info("加载配置文件: %s", fullfilename);
    } catch (exception& e) {
        this->error("加载配置文件失败: %s", e.what());
    }
}

void ScyllaGuiApp::save_file(const string& filename)
{
    ofstream outfile(filename);
    if (!outfile.is_open()) {
        this->error("打开文件 %s 失败", filename.c_str());
        return;
    }

    outfile << this->m_splug_view->getNode();
    this->m_config_file = filename;
    this->info("保存到 '%s'", filename.c_str());
}

void ScyllaGuiApp::save_file()
{
    if (this->m_config_file.empty())
        this->warn("No file name specified");

    this->save_file(this->m_config_file);
}

const std::string& ScyllaGuiApp::config_file() const {
    return this->m_config_file;
}

const YAML::Node& ScyllaGuiApp::config_node() const {
    return this->m_splug_view->get_origin_node();
}


void ScyllaGuiApp::add_collapsing_config(std::string key, std::string title, std::unique_ptr<GuiYamlNode> child) {
    this->m_splug_view->add_child(key, title, move(child));
}

YAML::Node ScyllaGuiApp::dump_node() const
{
    return this->m_splug_view->getNode();
}

std::string ScyllaGuiApp::dump() const
{
    stringstream ss;
    auto node = this->m_splug_view->getNode();
    ss << node;
    return ss.str();
}

int ScyllaGuiApp::render_frame()
{
    auto& io = ImGui::GetIO();
    auto viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowViewport(viewport->ID);
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);

    if (ImGui::Begin("MainWindow" , nullptr , 
                 ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
                 ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings | 
                 ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoScrollbar | 
                 ImGuiWindowFlags_NoScrollWithMouse))
    {
        if (ImGui::BeginChild("FileMenu", ImVec2(0, 20), false, ImGuiWindowFlags_NoScrollbar))
        {
            this->child_window_file_menu();
            ImGui::EndChild();
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        ImGui::Spacing();

        auto h = ImGui::GetWindowHeight();
        auto control_height = 240 + 30;
        if (this->m_dbgplugin_mode)
            control_height = 135;

        if (h > control_height + 30) {
            h -= control_height;
        } else {
            h = 30;
        }
        if (ImGui::BeginChild("config", ImVec2(0, h), false)) {
            if (this->m_splug_view)
                this->m_splug_view->show();
            ImGui::EndChild();
        }

        this->widget_log_line();

        ImGui::Spacing();
        if (ImGui::BeginChild("control", ImVec2(0, 0), true)) {
            this->child_window_control();
            ImGui::EndChild();
        }

        this->m_remote_log_window.show();
        this->m_local_log_window.show();
        
        ImGui::End();
    }

    return 0;
}

void ScyllaGuiApp::child_window_file_menu()
{
    if (ImGui::Button("打开")) {
        auto file = ChooserFile("YAML (*.yaml)\0*.yaml\0ALL Files (*.*)\0*.*\0");
        if (file != nullptr)
            this->open_file(file);
    }
    ImGui::SameLine();
    if (ImGui::Button("保存")) {
        if (!this->m_config_file.empty()) {
            this->save_file();
        } else {
            auto file = SaveFileTo("YAML (*.yaml)\0*.yaml\0ALL Files (*.*)\0*.*\0", "scylla.yaml");
            if (file != nullptr)
                this->save_file(file);
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("另存")) {
        auto file = SaveFileTo("YAML (*.yaml)\0*.yaml\0ALL Files (*.*)\0*.*\0", "scylla.yaml");
        if (file != nullptr)
            this->save_file(file);
    }
}

void ScyllaGuiApp::widget_log_line()
{
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

void ScyllaGuiApp::child_window_control()
{
    if (!this->m_dbgplugin_mode) {
        this->widget_operation_mode();

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        switch (m_mode)
        {
        case RunningMode_CMDLine:
            this->widget_new_process();
            break;
        case RunningMode_ProcessName:
            this->widget_process_name();
            break;
        case RunningMode_PID:
            this->widget_process_id();
            break;
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        this->widget_suspend_mod();
        ImGui::Spacing();
    }

    if (ImGui::Button("运行")) {
        this->m_injected = this->operation_doit();
    }

    if (!this->m_injected)
        ImGui::BeginDisabled();
    ImGui::SameLine();
    if (ImGui::Button("取消")) {
        this->operation_undo();
    }
    if (!this->m_injected)
        ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::Checkbox("远程日志窗口", &this->m_remote_log_window.visibility());

    ImGui::SameLine();
    ImGui::Checkbox("接收远程日志", &m_receive_remote_log);

    ImGui::SameLine();
    ImGui::Checkbox("本地日志窗口", &this->m_local_log_window.visibility());
}

void ScyllaGuiApp::widget_operation_mode()
{
    static const char* modes[] = {
        "新进程",
        "进程名称",
        "进程ID"
    };

    if (ImGui::BeginCombo("模式", modes[m_mode])) {
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
}

void ScyllaGuiApp::widget_new_process()
{
    ImGui::InputText("可执行文件", m_executable.get(), MAX_PATH);
    ImGui::SameLine();
    if (ImGui::Button("...")) {
        auto file = ChooserFile("Executable (*.exe)\0*.exe\0ALL Files (*.*)\0*.*\0");
        if (file != nullptr)
            strncpy(m_executable.get(), file, MAX_PATH);
    }

    ImGui::InputText("命令行参数", m_cmdline.get(), MAX_CMDLINE_ARGS_LEN);
}
void ScyllaGuiApp::widget_process_name()
{
    ImGui::InputText("进程名", m_process_name.get(), MAX_PATH);

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

void ScyllaGuiApp::widget_process_id()
{
    ImGui::InputInt("进程ID", &this->m_pid);
    ImGui::SameLine();
    if (ImGui::Button("***")) {
        this->m_process_select_window.refresh_processes();
        this->m_wait_for_process_select = true;
    }
    
    if (this->m_wait_for_process_select && !this->m_process_select_window.show()) {
        auto& s = this->m_process_select_window.get_selected();
        this->m_wait_for_process_select = false;
        if (s.m_pid != 0) {
            this->m_pid = s.m_pid;
            this->m_prev_pid = s.m_pid;
            this->process_name_by_pid = s.m_name;
        }
    }

    if (this->m_pid < 0)
        this->m_pid = 0;

    if (ImGui::Button("R") && this->m_pid > 0) {
        auto pn = GetProcessNameByPid(this->m_pid);
        if (pn != nullptr) {
            this->process_name_by_pid = pn;
            this->m_prev_pid = this->m_pid;
        } else {
            this->warn("找不到进程ID %d", this->m_pid);
        }
    }

    if (this->m_prev_pid == this->m_pid && !this->process_name_by_pid.empty()) {
        ImGui::SameLine();
        ImGui::Text(this->process_name_by_pid.c_str());
    }
}

void ScyllaGuiApp::widget_suspend_mod()
{
    static const char* suspendon[] = {
        "不暂停",
        "加载 kernel32.dll 后",
        "加载所有 dll 后",
        "系统断点",
        "程序入口 (EntryPoint)",
    };
    static SuspendingState suspendon_ss[] = {
        SUSPEND_ON_NO_SUSPEND,
        SUSPEND_ON_NTDLL_KERNEL32_LOADED,
        SUSPEND_ON_ALL_MODULE_LOADED,
        SUSPEND_ON_SYSTEM_BREAKPOINT,
        SUSPEND_ON_ENTRYPOINT,
    };

    static const char* suspendon2[] = {
        "不暂停",
        "暂停",
    };
    static SuspendingState suspendon2_ss[] = {
        SUSPEND_ON_NO_SUSPEND,
        SUSPEND_ON_ENTRYPOINT,
    };

    auto combo_op = suspendon2;
    auto combo_ss = suspendon2_ss;
    size_t combon = sizeof(suspendon2) / sizeof(suspendon2[0]);
    if (this->m_mode == RunningMode_CMDLine) {
        combo_op = suspendon;
        combo_ss = suspendon_ss;
        combon = sizeof(suspendon) / sizeof(suspendon[0]);
    }

    if (this->m_suspending_state_index >= combon)
        this->m_suspending_state_index = 0;

    auto index = this->m_suspending_state_index;
    if (ImGui::BeginCombo("暂停模式", combo_op[index])) {
        for (int i = 0; i < combon; i++) {
            const bool is_selected = (i == index);
            if (ImGui::Selectable(combo_op[i], is_selected)) {
                this->m_suspending_state_index = i;
                this->m_suspending_state = combo_ss[i];
            }
            if (is_selected)
                ImGui::SetItemDefaultFocus();
        }
        ImGui::EndCombo();
    }
    if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::Text("是否暂停程序再进行操作");
        ImGui::Text("某些暂停模式可能导致远程线程注入DLL出现死锁");
        ImGui::EndTooltip();
    }
}

void ScyllaGuiApp::set_pid(int pid)
{
    this->m_pid = pid;
    this->m_mode = RunningMode_PID;
}

bool ScyllaGuiApp::operation_doit()
{
    WinProcessNative::suspend_t suspend_state;
    SuspendingState sstate = this->m_suspending_state;
    bool need_suspend = sstate != SUSPEND_ON_NO_SUSPEND;

    if (this->m_mode == RunningMode_CMDLine) {
        string _exe(m_executable.get());
        string _cmdline(m_cmdline.get());
        try {
            this->m_process = nullptr;
            this->m_process = CreateProcessAndSuspend(_exe, _cmdline, sstate, suspend_state);
        } catch (exception& e) {
            this->error("%s", e.what());
            return false;
        }

        if (!this->m_process) {
            this->error("创建新进程失败");
            return false;
        }
    } else if (this->m_mode == RunningMode_ProcessName) {
        this->m_pid = GetPidByProcessName(this->m_process_name.get());

        if (this->m_pid == 0) {
            this->error("找不到进程 %s", this->m_process_name.get());
            return false;
        }

        try {
            this->m_process = make_shared<WinProcessNative>(this->m_pid);
        } catch (const std::exception& e) {
            this->warn("操作失败 '%s': %s", this->m_process_name.get(), e.what());
            return false;
        }
    } else if (this->m_mode == RunningMode_PID) {
        try {
            this->m_process = make_shared<WinProcessNative>(this->m_pid);
        } catch (const std::exception& e) {
            this->warn("操作失败 '%d': %s", this->m_pid, e.what());
            return false;
        }
    } else {
        this->error("Unknown running mode");
        return false;
    }

    if (need_suspend && !suspend_state) {
        suspend_state = this->m_process->suspendThread();
        if (!suspend_state) {
            this->warn("暂停线程失败");
            return false;
        }
    }

    auto log_server_config = make_shared<scylla::LogServerConfig>();
    log_server_config->data = this;
    log_server_config->is_callback_log_server = true;
    log_server_config->on_log = [](const char* log, int len, void* data) {
        auto self = static_cast<ScyllaGuiApp*>(data);
        if (!self->m_receive_remote_log)
            return;

        self->m_remote_log_window.add_log(string(log, len));
    };

    try {
        this->m_charybdis = make_unique<scylla::Charybdis>(this->m_process);
        auto config = this->m_charybdis->get_splug_config();
        config->set("logger", log_server_config);
        this->m_charybdis->set_log_client(this->m_local_logger);

        this->m_charybdis->doit(this->m_splug_view->getNode());
        this->m_injected = true;

        if (suspend_state && !this->m_process->resumeThread(std::move(suspend_state))) {
            this->warn("恢复线程失败");
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        this->warn("创建 Charybdis 失败: %s", e.what());
        return false;
    }
}

void ScyllaGuiApp::operation_undo()
{
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
        this->error("取消失败: %s", e.what());
    }
}

void ScyllaGuiApp::send(const char* msg, uint16_t len) {
    this->m_log_msg = string(msg, len);
    this->m_local_log_window.add_log(this->m_log_msg);
    this->m_log_prev_timestamp = std::chrono::system_clock::now();
}

void ScyllaGuiApp::info(const char* msg, ...) {
    this->m_log_level = Log_Info;
    va_list args;
    va_start(args, msg);
    this->send_var("", msg, args);
    va_end(args);
}
void ScyllaGuiApp::warn(const char* msg, ...) {
    this->m_log_level = Log_Warning;
    va_list args;
    va_start(args, msg);
    this->send_var("", msg, args);
    va_end(args);
}
void ScyllaGuiApp::error(const char* msg, ...) {
    this->m_log_level = Log_Error;
    va_list args;
    va_start(args, msg);
    this->send_var("", msg, args);
    va_end(args);
}
