#ifndef _SCYLLA_APP_H_
#define _SCYLLA_APP_H_

#include "logger/log_client.h"
#include "scylla/utils.h"
#include "scylla/charybdis.h"
#include "./imgui_app.h"
#include "./splug/splug_view.h"
#include "./widget/log_window.h"
#include "./widget/process_select_window.h"
#include <mutex>
#include <memory>
#include <string>
#include <vector>
#include <chrono>


class ScyllaGuiApp: public ImGuiAPP, protected LogClient
{
private:
    std::unique_ptr<GuiSplugView> m_splug_view;
    std::string m_config_file;

    LogWindow m_remote_log_window;
    bool m_receive_remote_log;

    LogWindow m_local_log_window;
    std::shared_ptr<LogClient> m_local_logger;

    enum RunningMode {
        RunningMode_CMDLine = 0,
        RunningMode_ProcessName,
        RunningMode_PID,
    } m_mode;

    std::shared_ptr<char> m_executable;
    std::shared_ptr<char> m_cmdline;
    std::shared_ptr<char> m_process_name;
    bool m_pid_resolved_by_process_name;
    int m_pid;
    int m_prev_pid;
    std::string process_name_by_pid;

    ProcessSelectWindow m_process_select_window;
    bool m_wait_for_process_select;

    int m_suspending_state_index;
    SuspendingState m_suspending_state;

    bool m_injected;
    int  m_injected_pid;
    std::shared_ptr<WinProcessNative> m_process;
    std::unique_ptr<scylla::Charybdis> m_charybdis;

    std::string m_log_msg;
    std::chrono::system_clock::time_point m_log_prev_timestamp;
    enum { Log_None, Log_Info, Log_Warning, Log_Error, } m_log_level;


/**----------------------------------
 * ------- Renderer Functions ------- */
    void child_window_file_menu();
    void widget_log_line();
    void child_window_control();
        void widget_operation_mode();
        void widget_new_process();
        void widget_process_name();
        void widget_process_id();
        void widget_suspend_mod();
/** ------- End Renderer Functions -------
 *  -------------------------------------- */

    bool operation_doit();
    void operation_undo();


protected:
    virtual int render_frame() override;
    virtual void send(const char* buf, uint16_t bufsize) override;
    void info(const char* fmt, ...);
    void warn(const char* fmt, ...);
    void error(const char* fmt, ...);


public:
    ScyllaGuiApp();

    void open_file(const std::string& filename);
    void save_file();
    void save_file(const std::string& filename);
    const std::string& config_file();

    std::string dump();
};

#endif // _SCYLLA_APP_H_