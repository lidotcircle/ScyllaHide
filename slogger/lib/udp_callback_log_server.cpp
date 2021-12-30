#include "logger/udp_callback_log_server.h"
using namespace std;


UDPCallbackLogServer::UDPCallbackLogServer(
    uint16_t port, uint32_t addr, 
    function<void(const char*, int, void*)> on_log, void* data
): UDPLogServer(port, addr), CallbackLog(on_log, data)
{
}
