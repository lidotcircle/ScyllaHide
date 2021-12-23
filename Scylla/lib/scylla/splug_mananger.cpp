#include "scylla/splug_manager.h"
#include <stdexcept>
using namespace std;


namespace scylla {

SPlugManager::SPlugManager(ScyllaContextPtr context): SPlug(context), m_done(false) {}

void SPlugManager::add_splug(const string& plugname, SPlugFactory plug_factory)
{
    if (std::find(m_plugs.begin(), m_plugs.end(), plugname) != m_plugs.end())
        throw std::runtime_error("SPlugManager:add_splug: plug " + plugname + " already exists");

    m_plugs.push_back(make_pair(plugname, std::move(plug_factory(this->context()))));
}

void SPlugManager::doit(const YAML::Node& node)
{
    if (this->m_done)
        throw std::runtime_error("SPlugManager::doit: already done");
    if (!node.IsMap())
        throw std::runtime_error("SPlugManager::doit: yaml node is not a map");

    if (node["disable"] && node["disable"].as<bool>())
        return;

    for (auto& plug : m_plugs) {
        if (node[plug.first]) {
            plug.second->doit(node[plug.first]);
            this->m_plugs_done.insert(plug.first);
        }
    }

    this->m_done = true;
}

void SPlugManager::undo()
{
    if (!this->m_done)
        throw std::runtime_error("SPlugManager::undo: not done");

    for (auto it=m_plugs.rbegin(); it!=m_plugs.rend(); ++it) {
        if (this->m_plugs_done.find(it->first) != this->m_plugs_done.end()) {
            it->second->undo();
            this->m_plugs_done.erase(it->first);
        }
    }

    this->m_done = false;
}

} // namespace scylla