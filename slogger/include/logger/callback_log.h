#ifndef _SCYLLA_CALLBACK_LOG_H_
#define _SCYLLA_CALLBACK_LOG_H_

#include "./log_server.h"
#include <functional>

class CallbackLog: public virtual LogServer {
private:
    std::function<void(const char*, int, void*)> _callback;
    void* data;

protected:
    CallbackLog(std::function<void(const char*, int, void*)> callback, void* data);

    virtual void consume_message(const char* msg, int len) override;
};

#endif // _SCYLLA_CALLBACK_LOG_H_