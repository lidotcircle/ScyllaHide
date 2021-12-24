#ifndef _SPLUG_LOG_SERVER_H_
#define _SPLUG_LOG_SERVER_H_

#include "../splug.h"
#include "../context_base.h"
#include "../../logger/log_server.h"
#include <memory>
#include <thread>


namespace scylla {

class SPlugLogServer: public SPlug {
private:
    std::unique_ptr<LogServer> m_log_server;
    std::unique_ptr<std::thread> m_log_server_poll_thread;

public:
    SPlugLogServer(ScyllaContextPtr context);

    virtual void doit(const YAML::Node& node) override;
    virtual void undo() override;

    virtual ~SPlugLogServer() override;
};

} // namespace scylla

#endif // _SPLUG_LOG_SERVER_H_