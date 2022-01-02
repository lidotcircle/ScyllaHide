#ifndef _SCYLLA_GUI_LOG_WINDOW_H_
#define _SCYLLA_GUI_LOG_WINDOW_H_

#include <mutex>
#include <vector>
#include <string>
#include "../ui_element.h"
#include "./pagination.h"


class LogWindow: public UIElement {
private:
    std::recursive_mutex m_mutex;
    std::vector<std::string> m_logs;
    Pagination m_pagination;
    std::string m_window_title;

public:
    LogWindow() = delete;
    LogWindow(const std::string& window_title);

    virtual bool show() override;

    void add_log(const std::string& log);
    void clear_log();
};

#endif // _SCYLLA_GUI_LOG_WINDOW_H_