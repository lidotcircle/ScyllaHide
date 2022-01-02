#ifndef _SCYLLA_GUI_PAGINATION_H_
#define _SCYLLA_GUI_PAGINATION_H_

#include <mutex>
#include <vector>
#include <string>
#include "../ui_element.h"


class Pagination: public UIElement {
private:
    size_t m_total_records;
    size_t m_pagesize;
    int m_pageindex;
    int m_pagesize_input;
    size_t m_begin, m_end;
    size_t m_abs_pageindex;
    size_t m_pagecount;

public:
    Pagination();

    virtual bool show() override;

    size_t get_pagesize() const;

    void set_pagesize(size_t size);
    void set_records(size_t records);

    size_t record_begin();
    size_t record_end();
};

#endif // _SCYLLA_GUI_PAGINATION_H_