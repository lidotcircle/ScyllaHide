#include "scylla/context_base.h"
#include <stdexcept>
using namespace std;


namespace scylla {

ScyllaContextItem::~ScyllaContextItem() {}


ScyllaContextBase::ScyllaContextBase(std::shared_ptr<WinProcessNative> process)
    : m_process(process)
    , m_exchange(process)
    , m_splug_config(make_shared<SPlugConfig>())
{
}

shared_ptr<WinProcessNative> ScyllaContextBase::process() {
    return m_process;
}
const shared_ptr<WinProcessNative> ScyllaContextBase::process() const {
    return m_process;
}

ExchangeDataMX& ScyllaContextBase::exchange() {
    return m_exchange;
}
const ExchangeDataMX& ScyllaContextBase::exchange() const {
    return m_exchange;
}

std::shared_ptr<SPlugConfig> ScyllaContextBase::splug_config() {
    return m_splug_config;
}
const std::shared_ptr<SPlugConfig> ScyllaContextBase::splug_config() const {
    return m_splug_config;
}
void ScyllaContextBase::set_splug_config(std::shared_ptr<SPlugConfig> config) {
    if (config == nullptr)
        throw invalid_argument("config is null");
    m_splug_config = config;
}

void ScyllaContextBase::add_item(const string& name, std::shared_ptr<ScyllaContextItem> item) {
    if (m_items.find(name) != m_items.end()) {
        throw runtime_error("ScyllaContextBase::add_item(): item with name '" + name + "' already exists");
    }

    m_items[name] = item;
}
void ScyllaContextBase::remove_item(const std::string& name) {
    auto it = m_items.find(name);
    if (it == m_items.end()) {
        throw runtime_error("ScyllaContextBase::remove_item(): item with name '" + name + "' not found");
    }

    m_items.erase(it);
}
shared_ptr<ScyllaContextItem> ScyllaContextBase::get_item(const string& name) {
    auto it = m_items.find(name);
    if (it == m_items.end())
        return nullptr;

    return it->second;
}
const shared_ptr<ScyllaContextItem> ScyllaContextBase::get_item(const string& name) const {
    auto it = m_items.find(name);
    if (it == m_items.end())
        return nullptr;

    return it->second;
}

ScyllaContextBase::~ScyllaContextBase() {}

} // namespace scylla