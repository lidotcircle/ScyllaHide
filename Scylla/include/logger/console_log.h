#ifndef _SCYLLA_CONSOLE_LOG_H_
#define _SCYLLA_CONSOLE_LOG_H_

#include "./log_server.h"

class ConsoleLog: public virtual LogServer {
protected:
    virtual void consume_message(const char* msg, int len) override;
};

#endif // _SCYLLA_CONSOLE_LOG_H_