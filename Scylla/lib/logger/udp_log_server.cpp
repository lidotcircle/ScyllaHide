#include "logger/udp_log_server.h"
#include "utils.hpp"
#include <Winsock2.h>
#include <fcntl.h>

#include <assert.h>
#include <string.h>
#include <string>
#include <iostream>
#include <stdexcept>
#include <memory>
using namespace std;

#pragma comment(lib, "ws2_32.lib")
#define BUFSIZE (1 << 16)
static WSADATA wsaData;

UDPLogServer::UDPLogServer(uint16_t udpPort, uint32_t addr):
    m_port(udpPort), m_addr(addr),
    m_socket(nullptr, [](int* fd) {})
{
    this->m_run = false;
    if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        throw std::runtime_error("UDPLogServer(): WSAStartup failed");
    }

    auto sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0)
        throw std::runtime_error("UDPLogServer(): unable to create udp socket");
    auto d1 = defer([&]() { if (!this->m_run) closesocket(sock); });

    struct sockaddr_in addr_in;
    addr_in.sin_family = AF_INET;
    addr_in.sin_addr.s_addr = this->m_addr;
    addr_in.sin_port = this->m_port;
    if (bind(sock, (struct sockaddr*)&addr_in, sizeof(addr_in)) < 0)
        throw std::runtime_error("UDPLogServer(): unable to bind udp socket");

    int sl = sizeof(addr_in);
    if (getsockname(sock, (struct sockaddr*)&addr_in, &sl) < 0 || addr_in.sin_family != AF_INET)
        throw std::runtime_error("UDPLogServer(): unable to get udp socket name");

    this->m_port = addr_in.sin_port;
    this->m_addr = addr_in.sin_addr.s_addr;
    this->m_socket = unique_ptr<int,void(*)(int*)>(new int(sock), [](int* s) { closesocket(*s); delete s; });
    this->m_run = true;
}

void UDPLogServer::poll() {
    if (!this->m_socket)
        throw std::runtime_error("UDPLogServer(): socket is not initialized");

    int fd = *this->m_socket.get();
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
        } else if (len == 1 && maxbuf[0] == '\0') {
            continue;
        } else {
            this->consume_message(maxbuf, len);
        }
    }
}

void UDPLogServer::stop() {
    if (!this->m_run)
        return;

    auto sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    auto d1 = defer([&]() { if (sock > 0) closesocket(sock); });
    if (sock <= 0)
        return;

    this->m_run = false;
    struct sockaddr_in addr_in;
    addr_in.sin_family = AF_INET;
    addr_in.sin_addr.s_addr = this->m_addr;
    addr_in.sin_port = this->m_port;

    sendto(sock, "", 1, 0, (struct sockaddr*)&addr_in, sizeof(addr_in));
}

uint32_t UDPLogServer::GetAddr() {
    return this->m_addr;
}

uint16_t UDPLogServer::GetPort() {
    return this->m_port;
}

UDPLogServer::~UDPLogServer() {
    WSACleanup();
}
