#pragma once


class LogClient {
private:
    int  m_socket;
    __int16 m_port;
    __int32 m_addr;

public:
    LogClient(__int16 port, __int32 addr);
    LogClient(const LogClient&) = delete;
    LogClient& operator=(const LogClient&) = delete;

    void send(const char* buf, __int32 bufsize);

    ~LogClient();
};


LogClient* logClient();

