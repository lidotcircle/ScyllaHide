#ifndef _SCYLLA_LOG_CLIENT_CALLBACK_H_
#define _SCYLLA_LOG_CLIENT_CALLBACK_H_

#include "./log_client.h"
#include <functional>


class LogClientCallback: public LogClient {
private:
    std::function<void(const char*, uint16_t, void* data)> m_callback;
    void* m_data;

public:
    LogClientCallback() = delete;
    LogClientCallback(std::function<void(const char*, uint16_t, void*)> callback, void* data);

    virtual void send(const char* buf, uint16_t bufsize) override;
};

#endif // _SCYLLA_LOG_CLIENT_CALLBACk_H_