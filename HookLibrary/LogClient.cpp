#include <Winsock2.h>
#include <new.h>
#include "HookMain.h"
#include "LogClient.h"

#pragma comment(lib, "ws2_32.lib")
WSADATA wsaData;


LogClient::LogClient() {
    WSAStartup(MAKEWORD(2, 2), &wsaData);
}

void LogClient::init(__int16 port, __int32 addr) {
    if (this->m_socket > 0) return;

    if (addr == 0)
        addr = 0x0100007F;

    this->m_addr = addr;
    this->m_port = port;
    this->m_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (this->m_socket <= 0) {
        MessageBox(nullptr, L"create udp socket failed, bye", L"Bad", 0);
    }
}

void LogClient::send(const char* buf, __int32 bufsize) {
    if (this->m_socket <= 0) return;
    if (bufsize >= (1 << 16)) return;

    struct sockaddr_in addr_in;
    addr_in.sin_family = AF_INET;
    addr_in.sin_addr.s_addr = this->m_addr;
    addr_in.sin_port = this->m_port;

    if (sendto(this->m_socket, buf, bufsize, 0, (struct sockaddr*)&addr_in, sizeof(addr_in)) != bufsize) {
        closesocket(this->m_socket);
        this->m_socket = 0;
    }
}

LogClient::~LogClient() {
    if (this->m_socket > 0) {
        closesocket(this->m_socket);
        this->m_socket = 0;
    }

    WSACleanup();
}

static char _bytes[sizeof(LogClient)] = { 0 };
LogClient* _logClient = nullptr;
LogClient* logClient() {
    if (_logClient != nullptr)
        return _logClient;

    _logClient = new ((LogClient*)&_bytes) LogClient();
    _logClient->init(HookDllData.udpIPCPort, HookDllData.udpIPCAddr);

    char hello[] = "hello server";
    _logClient->send(hello, sizeof(hello));

    return _logClient;
}

