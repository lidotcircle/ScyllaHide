#ifndef _SCYLLA_GUI_PROCESS_SELECT_WINDOW_H_
#define _SCYLLA_GUI_PROCESS_SELECT_WINDOW_H_

#include "../ui_element.h"
#include <vector>
#include <string>
#include <functional>


class ProcessSelectWindow : public UIElement {
private:
    struct ProcessState {
        std::string m_name;
        std::string m_pid_str;
        int m_pid;
    };
    std::vector<ProcessState> m_processes;
    ProcessState m_selected;

public:
    ProcessSelectWindow();

    void refresh_processes();
    ProcessState& get_selected();
    const ProcessState& get_selected() const;

    virtual bool show() override;
};

#endif // _SCYLLA_GUI_PROCESS_SELECT_WINDOW_H_