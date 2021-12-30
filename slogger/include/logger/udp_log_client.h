#ifndef _SCYLLA_UDP_LOG_CLIENT_H_
#define _SCYLLA_UDP_LOG_CLIENT_H_

#include "./log_client.h"
#include <stdint.h>

class UDPLogClient: public LogClient {
private:
    int m_socket;
    uint16_t m_port;
    uint32_t m_addr;

public:
    UDPLogClient(uint16_t port, uint32_t addr);
    UDPLogClient(const UDPLogClient&) = delete;
    UDPLogClient(UDPLogClient&&) = delete;
    UDPLogClient& operator=(const UDPLogClient&) = delete;
    UDPLogClient& operator=(UDPLogClient&&) = delete;

    virtual void send(const char* buf, uint16_t bufsize) override;

    virtual ~UDPLogClient() override;
};

#endif // _SCYLLA_UDP_LOG_CLIENT_H_