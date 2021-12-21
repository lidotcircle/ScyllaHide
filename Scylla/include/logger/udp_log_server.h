#ifndef _SCYLLA_UDP_LOG_SERVER_H_
#define _SCYLLA_UDP_LOG_SERVER_H_

#include <stdint.h>
#include <memory>
#include "log_server.h"


class UDPLogServer : public virtual LogServer {
private:
    bool m_run;
    std::unique_ptr<int,void(*)(int*)> m_socket;
    uint16_t m_port;
    uint32_t m_addr;

public:
    UDPLogServer(uint16_t port = 0, uint32_t addr = 0x0100007F);

    uint32_t GetAddr();
    uint16_t GetPort();

    virtual void poll() override;
    virtual void stop() override;

    virtual ~UDPLogServer() override;
};

#endif // _SCYLLA_UDP_LOG_SERVER_H_