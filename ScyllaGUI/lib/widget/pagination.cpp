#include "scyllagui/widget/pagination.h"
#include <imgui.h>
using namespace std;


class pagination_info {
private:
    size_t total_count;
    size_t page_size;
    int    page_index;

public:
    pagination_info() = delete;
    pagination_info(size_t total_count, size_t page_size, int page_index)
        : total_count(total_count), page_size(page_size), page_index(page_index)
    {
        page_count = total_count / page_size;
        if (total_count % page_size != 0)
            page_count++;
        
        if (page_index < 0)
            page_index += (page_count + 1);

        if (page_index > page_count || page_index == 0)
            page_index = 1;

        abs_page_index = page_index;
        begin_index = (page_index - 1) * page_size;
        end_index = begin_index + page_size;
        if (end_index > total_count)
            end_index = total_count;
    }

    size_t page_count;
    size_t abs_page_index;
    size_t begin_index;
    size_t end_index;
};


Pagination::Pagination()
{
    m_pagesize = 10;
    m_pageindex = 0;
    m_pagesize_input = 10;
    this->set_records(0);
}

size_t Pagination::get_pagesize() const {
    return m_pagesize;
}

size_t Pagination::record_begin() {
    return m_begin;
}

size_t Pagination::record_end() {
    return m_end;
}

void Pagination::set_pagesize(size_t size) {
    m_pagesize = size;
    this->set_records(m_total_records);
}

void Pagination::set_records(size_t records) {
    this->m_total_records = records;

    pagination_info paginfo(records, this->m_pagesize, this->m_pageindex);
    this->m_begin = paginfo.begin_index;
    this->m_end   = paginfo.end_index;
    this->m_abs_pageindex = paginfo.abs_page_index;
    this->m_pagecount = paginfo.page_count;
}

bool Pagination::show() {
    if (!this->visibility())
        return false;

    auto width = ImGui::GetContentRegionAvail().x;
    auto gluewidth = (width - 150) / 2;
    ImGui::Dummy(ImVec2(gluewidth, 0));
    ImGui::SameLine();

    if (this->m_abs_pageindex == 1)
        ImGui::BeginDisabled();
    if (ImGui::Button("<<")) {
        this->m_pageindex = 1;
        this->set_records(this->m_total_records);
    }
    if (this->m_abs_pageindex == 1)
        ImGui::EndDisabled();
    
    if (this->m_abs_pageindex > 1) {
        ImGui::SameLine();
        if (ImGui::Button(to_string(this->m_abs_pageindex - 1).c_str())) {
            this->m_pageindex = this->m_abs_pageindex - 1;
            this->set_records(this->m_total_records);
        }
    }

    ImGui::SameLine();
    ImGui::Text("%d/%d", this->m_abs_pageindex, this->m_pagecount);

    if (this->m_abs_pageindex < this->m_pagecount) {
        ImGui::SameLine();
        if (ImGui::Button(to_string(this->m_abs_pageindex + 1).c_str())) {
            this->m_pageindex = this->m_abs_pageindex + 1;
            this->set_records(this->m_total_records);
        }
    }

    ImGui::SameLine();
    if (this->m_abs_pageindex == this->m_pagecount)
        ImGui::BeginDisabled();
    if (ImGui::Button(">>")) {
        this->m_pageindex = -1;
        this->set_records(this->m_total_records);
    }
    if (this->m_abs_pageindex == this->m_pagecount)
        ImGui::EndDisabled();
    
    ImGui::SameLine();
    ImGui::Text("每页%d条", this->m_pagesize);

    ImGui::Dummy(ImVec2(gluewidth, 0));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(50);
    if (ImGui::InputInt("##page_size", &this->m_pagesize_input, 0)) {
        if (this->m_pagesize_input < 8)
            this->m_pagesize_input = 8;
        
        if (this->m_pagesize_input > 200)
            this->m_pagesize_input = 200;
    }
    if (ImGui::IsItemHovered()) {
        ImGui::BeginTooltip();
        ImGui::Text("输入每页显示的条目数, 8 ~ 200");
        ImGui::EndTooltip();
    }
    ImGui::SameLine();
    if (ImGui::Button("确认")) {
        this->m_pagesize = this->m_pagesize_input;
        this->m_pageindex = 1;
    }
}