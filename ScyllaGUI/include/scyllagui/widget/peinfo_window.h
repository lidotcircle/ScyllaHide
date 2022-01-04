#ifndef _SCYLLA_GUI_PEINFO_WINDOW_H_
#define _SCYLLA_GUI_PEINFO_WINDOW_H_

#include "../ui_element.h"
#include "process/memory_map_pefile.h"
#include <vector>
#include <string>
#include <functional>


class PEInfoWindow : public UIElement {
private:
    std::shared_ptr<MemoryMapPEFile> m_pefile;
    std::vector<std::string> m_exports;
    std::string m_modulename;
    std::string m_title;

public:
    PEInfoWindow();
    PEInfoWindow(std::string modname, std::shared_ptr<MemoryMapPEFile> pefile);

    virtual bool show() override;
};

#endif // _SCYLLA_GUI_PEINFO_WINDOW_H_