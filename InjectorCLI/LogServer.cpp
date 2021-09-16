#include <Winsock2.h>
#include <fcntl.h>

#include <assert.h>
#include <string.h>
#include <iostream>

#include "LogServer.h"

#pragma comment(lib, "ws2_32.lib")
#define BUFSIZE (1 << 16)
WSADATA wsaData;

LogServer::LogServer(uint16_t udpPort, uint32_t addr): m_port(udpPort), m_addr(addr)
{
    this->m_run = true;
    this->m_socket = 0;

    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cout << "WSAStartup failed: " << iResult << std::endl;
    }
}

void LogServer::init()
{
    assert(this->m_socket <= 0);

    this->m_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    std::cout << this->m_socket << std::endl;
    std::cout << GetLastError() << std::endl;

    struct sockaddr_in addr_in;
    addr_in.sin_family = AF_INET;
    addr_in.sin_addr.s_addr = this->m_addr;
    addr_in.sin_port = this->m_port;
    if (this->m_socket > 0) {
        if (bind(this->m_socket, (struct sockaddr*)&addr_in, sizeof(addr_in)) < 0) {
            this->m_socket = 0;
        }
        else {
            int sl = sizeof(addr_in);
            if (getsockname(this->m_socket, (struct sockaddr*)&addr_in, &sl) < 0 || addr_in.sin_family != AF_INET) {
                closesocket(this->m_socket);
                this->m_socket = 0;
            }
            else {
                this->m_port = addr_in.sin_port;
                this->m_addr = addr_in.sin_addr.s_addr;
            }
        }
    } else {
        std::cout << "unable to create udp socket" << std::endl;
        abort();
    }
}

void LogServer::poll()
{
    int fd = this->m_socket;
    assert(fd > 0);
    char maxbuf[BUFSIZE];

    while (this->m_run) {
        errno = 0;
        int len = recvfrom(fd, maxbuf, sizeof(maxbuf), 0, NULL, NULL);
        if (len <= 0) {
            char error = 0;
            int l = sizeof(error);
            int r = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &l);
            if (r != 0 || error != 0 || l == 0) {
                closesocket(fd);
                this->m_socket = 0;
                return;
            }
        }
        else {
            this->new_message(maxbuf, len);
        }
    }

    closesocket(fd);
    return;
}

void LogServer::new_message(const char* buf, int len)
{
    char* bufn = new char[len + 1];
    memcpy(bufn, buf, len);
    bufn[len] = 0;
    std::cout << "message: " << bufn << std::endl;
}

uint32_t LogServer::GetAddr() {
    return this->m_addr;
}

uint16_t LogServer::GetPort()
{
    return this->m_port;
}

LogServer::~LogServer()
{
    WSACleanup();
}

