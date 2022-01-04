#ifndef _SCYLLA_CHARYBDIS_H_
#define _SCYLLA_CHARYBDIS_H_

#include "./splug_manager.h"
#include "./context_base.h"
#include "./process/win_process_native.h"
#include "./splug_config.h"


namespace scylla {

class Charybdis {
private:
    std::unique_ptr<SPlugManager> m_splug_manager;
    ScyllaContextPtr m_context;

public:
    Charybdis(WinProcess_t process);

    void doit_string(const std::string& yaml_string);
    void doit_file(const std::string& filename);
    void doit(const YAML::Node& node);

    void undo();

    std::shared_ptr<SPlugConfig> get_splug_config();
    const std::shared_ptr<SPlugConfig> get_splug_config() const;
    void set_splug_config(std::shared_ptr<SPlugConfig> confit);

    void set_log_client(std::shared_ptr<LogClient> log_client);
};

} // namespace scylla

#endif // _SCYLLA_CHARYBDIS_H_