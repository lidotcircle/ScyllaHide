#include "scyllagui/splug/peb_patch.h"
#include <stdexcept>
#include <imgui.h>
#include <Windows.h>
using namespace std;


GuiSplugPebPatch::GuiSplugPebPatch(const YAML::Node& node) {
    m_being_debugged = node["BeingDebugged"].as<bool>(false);
    m_ntglobal_flag = node["NtGlobalFlag"].as<bool>(false);
    m_process_parameters = node["ProcessParameters"].as<bool>(false);
    m_heap_flags = node["HeapFlags"].as<bool>(false);
    m_osbuild_number = node["OSBuildNumber"].as<bool>(false);
}

YAML::Node GuiSplugPebPatch::getNode() {
    YAML::Node node;
    node["BeingDebugged"] = m_being_debugged;
    node["NtGlobalFlag"] = m_ntglobal_flag;
    node["ProcessParameters"] = m_process_parameters;
    node["HeapFlags"] = m_heap_flags;
    node["OSBuildNumber"] = m_osbuild_number;
    return node;
}

bool GuiSplugPebPatch::show() {
    if (!this->visibility())
        return false;

    ImGui::Checkbox("BeingDebugged", &m_being_debugged);
    ImGui::Checkbox("NtGlobalFlag", &m_ntglobal_flag);
    ImGui::Checkbox("ProcessParameters", &m_process_parameters);
    ImGui::Checkbox("HeapFlags", &m_heap_flags);
    ImGui::Checkbox("OSBuildNumber", &m_osbuild_number);

    return true;
}
