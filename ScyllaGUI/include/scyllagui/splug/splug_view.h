#ifndef _SCYLLA_GUI_SPLUG_VIEW_H_
#define _SCYLLA_GUI_SPLUG_VIEW_H_

#include "../yaml_map.h"
#include <yaml-cpp/yaml.h>


class GuiSplugView: public GuiYamlMap
{
public:
    GuiSplugView(const YAML::Node& node, bool dbgplugin_mode);
};

#endif // _SCYLLA_GUI_SPLUG_VIEW_H_