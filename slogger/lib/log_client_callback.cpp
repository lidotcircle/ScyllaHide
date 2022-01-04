#include "logger/log_client_callback.h"


LogClientCallback::LogClientCallback(std::function<void(const char*, uint16_t, void* data)> callback, void* data)
    : m_callback(callback), m_data(data)
{
}

void LogClientCallback::send(const char* buf, uint16_t bufsize)
{
    m_callback(buf, bufsize, m_data);
}