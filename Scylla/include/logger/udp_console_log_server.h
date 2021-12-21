#ifndef _SCYLLA_UDP_CONSOLE_LOG_SERVER_H_
#define _SCYLLA_UDP_CONSOLE_LOG_SERVER_H_

#include "./console_log.h"
#include "./udp_log_server.h"

class UDPConsoleLogServer: public UDPLogServer, public ConsoleLog {
public:
    UDPConsoleLogServer(uint16_t port = 0, uint32_t addr = 0x1000007F);
};

#endif // _SCYLLA_UDP_CONSOLE_LOG_SERVER_H_