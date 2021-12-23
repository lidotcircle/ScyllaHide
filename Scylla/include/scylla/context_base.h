#ifndef _SCYLLA_CONTEXT_BASE_H_
#define _SCYLLA_CONTEXT_BASE_H_

#include <memory>
#include <map>
#include <string>
#include "./exchange_mx.h"

class WinProcessNative;


namespace scylla {


class ScyllaContextItem {
public:
    virtual ~ScyllaContextItem();
};


class ScyllaContextBase {
private:
    std::shared_ptr<WinProcessNative> m_process;
    ExchangeDataMX m_exchange;
    std::map<std::string, std::shared_ptr<ScyllaContextItem>> m_items;

public:
    ScyllaContextBase() = delete;
    ScyllaContextBase(std::shared_ptr<WinProcessNative> process);

    std::shared_ptr<WinProcessNative> process();
    const std::shared_ptr<WinProcessNative> process() const;

    ExchangeDataMX& exchange();
    const ExchangeDataMX& exchange() const;

    void add_item(const std::string& name, std::shared_ptr<ScyllaContextItem> item);
    std::shared_ptr<ScyllaContextItem> get_item(const std::string& name);
    const std::shared_ptr<ScyllaContextItem> get_item(const std::string& name) const;

    virtual ~ScyllaContextBase();
};


using ScyllaContextPtr = std::shared_ptr<ScyllaContextBase>;

} // namespace scylla

#endif // _SCYLLA_CONTEXT_BASE_H_