#ifndef _SCYLLA_CONSOLE_LOG_CLIENT_H_
#define _SCYLLA_CONSOLE_LOG_CLIENT_H_

#include "./log_client.h"


class LogClientConsole: public LogClient {
public:
    virtual void send(const char* buf, uint16_t bufsize) override;
};

#endif // _SCYLLA_CONSOLE_LOG_CLIENT_H_