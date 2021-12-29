#ifndef _SCYLLA_UDP_CALLBACK_LOG_SERVER_H_
#define _SCYLLA_UDP_CALLBACK_LOG_SERVER_H_

#include "./callback_log.h"
#include "./udp_log_server.h"

class UDPCallbackLogServer: public UDPLogServer, public CallbackLog {
public:
    UDPCallbackLogServer(uint16_t port, uint32_t addr,
                         std::function<void(const char*, int, void*)> on_log, void* data);
};

#endif // _SCYLLA_UDP_CALLBACK_LOG_SERVER_H_