#ifndef _SCYLLA_SPLUG_CONFIG_H_
#define _SCYLLA_SPLUG_CONFIG_H_

#include <memory>
#include <string>
#include <map>

class SPlugConfigItem {
public:
    virtual ~SPlugConfigItem();
};

class SPlugConfig {
private:
    std::map<std::string, std::shared_ptr<SPlugConfigItem>> m_items;

public:
    virtual ~SPlugConfig();

    void set(const std::string& name, std::shared_ptr<SPlugConfigItem> item);
    std::shared_ptr<SPlugConfigItem> get(const std::string& name);
};

#endif // _SCYLLA_SPLUG_CONFIG_H_