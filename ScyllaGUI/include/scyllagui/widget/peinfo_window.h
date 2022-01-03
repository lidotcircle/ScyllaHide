#ifndef _SCYLLA_GUI_PEINFO_WINDOW_H_
#define _SCYLLA_GUI_PEINFO_WINDOW_H_

#include "../ui_element.h"
#include "process/pe_header.h"
#include <vector>
#include <string>
#include <functional>


class PEInfoWindow : public UIElement {
private:
    std::vector<std::string> m_exports;
    std::string m_modulename;
    std::string m_title;
    PEHeader m_header;

public:
    PEInfoWindow();
    PEInfoWindow(std::vector<std::string> exports, std::string modulename, PEHeader header);

    virtual bool show() override;
};

#endif // _SCYLLA_GUI_PEINFO_WINDOW_H_