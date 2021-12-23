#include "scylla/context_base.h"
#include <stdexcept>
using namespace std;


namespace scylla {

ScyllaContextBase::ScyllaContextBase(std::shared_ptr<WinProcessNative> process)
    : m_process(process)
    , m_exchange(process)
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

void ScyllaContextBase::add_item(const string& name, std::shared_ptr<ScyllaContextItem> item) {
    if (m_items.find(name) != m_items.end()) {
        throw runtime_error("ScyllaContextBase::add_item(): item with name '" + name + "' already exists");
    }

    m_items[name] = item;
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