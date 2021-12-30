#include <new.h>
#include "exchange_data.h"
#include "logger/udp_log_client.h"
#include "hook_log_client.h"


static char _bytes[sizeof(LogClient)] = { 0 };
LogClient* _logClient = nullptr;
LogClient* logClient() {
    if (_logClient != nullptr)
        return _logClient;

    _logClient = new ((LogClient*)&_bytes) UDPLogClient(exchange_data.m_udp_port, exchange_data.m_udp_addr);

    char hello[] = "hello server";
    _logClient->send(hello, sizeof(hello));

    return _logClient;
}
