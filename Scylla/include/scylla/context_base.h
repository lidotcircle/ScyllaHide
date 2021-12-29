#ifndef _SCYLLA_CONTEXT_BASE_H_
#define _SCYLLA_CONTEXT_BASE_H_

#include <memory>
#include <map>
#include <string>
#include "./exchange_mx.h"
#include "./splug_config.h"

class WinProcessNative;


namespace scylla {


class ScyllaContextItem {
public:
    virtual ~ScyllaContextItem();
};


class ScyllaContextBase {
private:
    std::shared_ptr<WinProcessNative> m_process;
    std::shared_ptr<SPlugConfig> m_splug_config;
    ExchangeDataMX m_exchange;
    std::map<std::string, std::shared_ptr<ScyllaContextItem>> m_items;

public:
    ScyllaContextBase() = delete;
    ScyllaContextBase(std::shared_ptr<WinProcessNative> process);

    std::shared_ptr<WinProcessNative> process();
    const std::shared_ptr<WinProcessNative> process() const;

    ExchangeDataMX& exchange();
    const ExchangeDataMX& exchange() const;

    std::shared_ptr<SPlugConfig> splug_config();
    const std::shared_ptr<SPlugConfig> splug_config() const;
    void set_splug_config(std::shared_ptr<SPlugConfig> config);

    void add_item(const std::string& name, std::shared_ptr<ScyllaContextItem> item);
    void remove_item(const std::string& name);
    std::shared_ptr<ScyllaContextItem> get_item(const std::string& name);
    const std::shared_ptr<ScyllaContextItem> get_item(const std::string& name) const;

    template<typename T>
    std::shared_ptr<T> get_item(const std::string& name) {
        auto it = m_items.find(name);
        if (it == m_items.end())
            return nullptr;

        return std::dynamic_pointer_cast<T>(it->second);
    }

    template<typename T>
    const std::shared_ptr<T> get_item(const std::string& name) const {
        auto it = m_items.find(name);
        if (it == m_items.end())
            return nullptr;

        return std::dynamic_pointer_cast<T>(it->second);
    }

    virtual ~ScyllaContextBase();
};


using ScyllaContextPtr = std::shared_ptr<ScyllaContextBase>;

} // namespace scylla

#endif // _SCYLLA_CONTEXT_BASE_H_