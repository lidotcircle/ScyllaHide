#include "process/memory_map_pefile.h"
#include "scylla/splug/dll_injector.h"
#include "scyllagui/splug/dll_injector.h"
#include "scylla_constants.h"
#include "scylla/utils.h"
#include "str_utils.h"
#include <imgui.h>
#include <stdexcept>
using namespace std;
using namespace scylla;

#define MAX_ADDR_LEN 256

static string string_trim(string str)
{
    str.erase(0, str.find_first_not_of(" \t\r\n"));
    str.erase(str.find_last_not_of(" \t\r\n") + 1);
    return str;
}

DLLInjectState::DLLInjectState():
    enable(true), stealthy(false),
    deleted(false), is_internal(false),
    m_is_valid(false)
{
    this->dll_path = shared_ptr<char>(new char[MAX_ADDR_LEN], std::default_delete<char[]>());
    this->exchange = shared_ptr<char>(new char[MAX_ADDR_LEN], std::default_delete<char[]>());
    strncpy(this->dll_path.get(), "", MAX_ADDR_LEN);
    strncpy(this->exchange.get(), "", MAX_ADDR_LEN);
}

void DLLInjectState::refresh()
{
    if (_strnicmp(this->dll_path.get(), this->m_old_dll_path.c_str(), MAX_ADDR_LEN) == 0)
        return;

    std::string cdll_path(this->dll_path.get());
    this->m_old_dll_path = cdll_path;

    try {
        shared_ptr<MemoryMapPEFile> pefile;
        
        if (_strnicmp(cdll_path.c_str(), ANTIANTI_DLL, sizeof(ANTIANTI_DLL)) == 0) {
            vector<char> data(hook_library_data, hook_library_data + hook_library_data_size);
            pefile = make_shared<MemoryMapPEFile>(data);
        } else {
            pefile = make_shared<MemoryMapPEFile>(cdll_path);
        }

        this->m_info_window = PEInfoWindow(canonicalizeModuleName(cdll_path), pefile);
        this->m_is_valid = true;
    } catch (exception& err) {
        this->m_is_valid = false;
    }
}

GuiSplugDllInjector::GuiSplugDllInjector(const YAML::Node& node) {
    if (!node.IsSequence() && node.IsDefined())
        throw std::runtime_error("GuiSplugDllInjector: node is not a sequence");
    
    bool found_antianti = false;

    for (size_t i=0;i<node.size();i++) {
        auto& item = node[i];
        if (!item.IsMap())
            throw std::runtime_error("GuiSplugDllInjector: item is not a map");

        DLLInjectState state;
        state.enable = !item["disable"].as<bool>(false);
        state.stealthy = item["stealthy"].as<bool>(false);
        string dll_path = item["path"].as<string>();
        string exchange = item["exchange"].as<string>("");

        if (dll_path == ANTIANTI_DLL) {
            state.is_internal = true;
            found_antianti = true;
        }

        if (dll_path.empty())
            throw std::runtime_error("GuiSplugDllInjector: dll_path is empty");
        
        strncpy(state.dll_path.get(), dll_path.c_str(), MAX_ADDR_LEN);
        strncpy(state.exchange.get(), exchange.c_str(), MAX_ADDR_LEN);
        state.refresh();

        this->m_dlls.push_back(state);
    }

    if (!found_antianti) {
        DLLInjectState state;
        state.is_internal = true;
        strncpy(state.dll_path.get(), ANTIANTI_DLL, MAX_ADDR_LEN);
        strncpy(state.exchange.get(), ANTIANTI_DLL_EXCHANGE_SYMBOL, MAX_ADDR_LEN);

        state.refresh();
        this->m_dlls.insert(this->m_dlls.begin(), state);
    }
}

YAML::Node GuiSplugDllInjector::getNode() {
    YAML::Node node;

    for (auto& state : this->m_dlls) {
        YAML::Node item;
        item["disable"] = !state.enable;
        item["stealthy"] = state.stealthy;
        string path(state.dll_path.get());
        string exch(state.exchange.get());
        path = string_trim(path);
        exch = string_trim(exch);
        if (path.empty()) {
            state.deleted = true;
            continue;
        }

        item["path"] = path;
        if (!exch.empty())
            item["exchange"] = exch;

        node.push_back(item);
    }

    return node;
}

bool GuiSplugDllInjector::show() {
    if (!this->visibility())
        return false;

    vector<size_t> deleted_s;

    for (size_t i=0;i<this->m_dlls.size();i++) {
        ImGui::PushID(i);

        auto& state = this->m_dlls[i];
        bool is_internal = state.is_internal;

        if (state.deleted) {
            deleted_s.push_back(i);
            continue;
        }

        bool is_valid = state.m_is_valid;
        if (!is_valid)
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.0f, 0.0f, 1.0f));

        ImVec2 dummy(20, 0);
        ImGui::Checkbox("启用", &state.enable);
        ImGui::SameLine();
        ImGui::Dummy(dummy);
        ImGui::SameLine();
        ImGui::Checkbox("内存注入", &state.stealthy);
        if (state.m_is_valid) {
            ImGui::SameLine();
            ImGui::Checkbox("模块信息窗口", &state.m_info_window.visibility());
            state.m_info_window.show();
        }

        if (!is_valid)
            ImGui::PopStyleColor();

        if (is_internal)
            ImGui::BeginDisabled();

        ImGui::InputText("DLL路径", state.dll_path.get(), MAX_ADDR_LEN);
        ImGui::SameLine();
        if (ImGui::Button("...")) {
            auto path = ChooserFile("DLL Files (*.dll)\0*.dll\0ALL Files (*.*)\0*.*\0");
            if (path)
                strncpy(state.dll_path.get(), path, MAX_ADDR_LEN);
        }
        ImGui::InputText("exchange 导出符号", state.exchange.get(), MAX_ADDR_LEN);

        if (is_internal)
            ImGui::EndDisabled();

        if (ImGui::BeginPopupModal("Delete?")) {
            ImGui::Text("确认删除 ?");
            if (ImGui::Button("是")) {
                state.deleted = true;
                ImGui::CloseCurrentPopup();
            }
            ImGui::SameLine();
            if (ImGui::Button("否")) {
                ImGui::CloseCurrentPopup();
            }
            ImGui::EndPopup();
        }
        if (!is_internal && ImGui::Button("删除"))
            ImGui::OpenPopup("Delete?");
        
        state.refresh();

        ImGui::PopID();
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
    }

    for (auto& it = deleted_s.rbegin();it!=deleted_s.rend();it++)
        this->m_dlls.erase(this->m_dlls.begin() + *it);

    auto width = ImGui::GetWindowWidth();
    auto add_size = ImVec2(width * 0.4, 35);
    ImGui::Dummy(ImVec2((width - add_size.x) / 2, 0));
    ImGui::SameLine();
    if (ImGui::Button("新增", add_size)) {
        DLLInjectState state;
        this->m_dlls.push_back(state);
    }

    return true;
}