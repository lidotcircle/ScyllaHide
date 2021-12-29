#include "scylla/splug_config.h"
#include <stdexcept>
using namespace std;


SPlugConfigItem::~SPlugConfigItem() {}

SPlugConfig::~SPlugConfig() {}

shared_ptr<SPlugConfigItem> SPlugConfig::get(const string& name) {
    auto it = m_items.find(name);
    if (it == m_items.end()) {
        return nullptr;
    }
    return it->second;
}

void SPlugConfig::set(const string& name, shared_ptr<SPlugConfigItem> item) {
    this->m_items[name] = item;
}