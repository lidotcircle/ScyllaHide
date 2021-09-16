#pragma once

class LogServer {
private:
    bool m_run;

    int  m_socket;
    uint16_t m_port;
    uint32_t m_addr;


    void new_message(const char* buf, int bufsize);

public:
    LogServer(uint16_t port = 0, uint32_t addr = 0x0100007F);
    LogServer() = delete;
    LogServer(const LogServer&) = delete;
    LogServer& operator=(const LogServer&) = delete;

    void poll();
    void init();

    uint32_t GetAddr();
    uint16_t GetPort();

    ~LogServer();
};

