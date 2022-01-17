#ifndef _SCYLLA_GUI_PEINFO_WINDOW_H_
#define _SCYLLA_GUI_PEINFO_WINDOW_H_

#include "../ui_element.h"
#include "process/memory_map_pefile.h"
#include <vector>
#include <string>
#include <functional>


class PEInfoWindow : public UIElement {
private:
    using addr_t = MapPEModule::addr_t;
    std::shared_ptr<MemoryMapPEFile> m_pefile;
    std::string m_modulename;
    std::string m_title;

    void show_basic_info() const;
    void show_exports() const;
    void show_imports() const;

public:
    PEInfoWindow();
    PEInfoWindow(std::string modname, std::shared_ptr<MemoryMapPEFile> pefile);

    virtual bool show() override;
};

#endif // _SCYLLA_GUI_PEINFO_WINDOW_H_