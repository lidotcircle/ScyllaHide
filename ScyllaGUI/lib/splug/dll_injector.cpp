#include "scyllagui/splug/dll_injector.h"
#include <imgui.h>
#include <stdexcept>
using namespace std;

#define MAX_ADDR_LEN 256

static string string_trim(string str)
{
    str.erase(0, str.find_first_not_of(" \t\r\n"));
    str.erase(str.find_last_not_of(" \t\r\n") + 1);
    return str;
}

GuiSplugDllInjector::GuiSplugDllInjector(const YAML::Node& node) {
    if (!node.IsSequence() && node.IsDefined())
        throw std::runtime_error("GuiSplugDllInjector: node is not a sequence");

    for (size_t i=0;i<node.size();i++) {
        auto& item = node[i];
        if (!item.IsMap())
            throw std::runtime_error("GuiSplugDllInjector: item is not a map");

        DLLInjectState state;
        state.enable = !item["disable"].as<bool>(false);
        state.stealthy = item["stealthy"].as<bool>(false);
        string dll_path = item["path"].as<string>();
        string exchange = item["exchange"].as<string>("");

        if (dll_path.empty())
            throw std::runtime_error("GuiSplugDllInjector: dll_path is empty");
        
        state.dll_path = shared_ptr<char>(new char[MAX_ADDR_LEN], std::default_delete<char[]>());
        state.exchange = shared_ptr<char>(new char[MAX_ADDR_LEN], std::default_delete<char[]>());

        strncpy(state.dll_path.get(), dll_path.c_str(), MAX_ADDR_LEN);
        strncpy(state.exchange.get(), exchange.c_str(), MAX_ADDR_LEN);
        state.deleted = false;

        this->m_dlls.push_back(state);
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

        if (state.deleted) {
            deleted_s.push_back(i);
            continue;
        }

        ImVec2 dummy(20, 0);
        ImGui::Checkbox("Enable", &state.enable);
        ImGui::SameLine();
        ImGui::Dummy(dummy);
        ImGui::SameLine();
        ImGui::Checkbox("Stealthy", &state.stealthy);

        ImGui::InputText("DLL Path", state.dll_path.get(), MAX_ADDR_LEN);
        ImGui::InputText("Export Data Symbol", state.exchange.get(), MAX_ADDR_LEN);

        if (ImGui::BeginPopupModal("Delete?")) {
            ImGui::Text("Are you sure you want to delete this item?");
            if (ImGui::Button("Yes")) {
                state.deleted = true;
                ImGui::CloseCurrentPopup();
            }
            ImGui::SameLine();
            if (ImGui::Button("No")) {
                ImGui::CloseCurrentPopup();
            }
            ImGui::EndPopup();
        }
        if (ImGui::Button("Delete"))
            ImGui::OpenPopup("Delete?");

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
    if (ImGui::Button("Add", add_size)) {
        DLLInjectState state;
        state.enable = true;
        state.stealthy = false;
        state.dll_path = shared_ptr<char>(new char[MAX_ADDR_LEN], std::default_delete<char[]>());
        state.exchange = shared_ptr<char>(new char[MAX_ADDR_LEN], std::default_delete<char[]>());
        strncpy(state.dll_path.get(), "", MAX_ADDR_LEN);
        strncpy(state.exchange.get(), "", MAX_ADDR_LEN);
        state.deleted = false;
        this->m_dlls.push_back(state);
    }

    return true;
}