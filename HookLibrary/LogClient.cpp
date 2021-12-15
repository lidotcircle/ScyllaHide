#include <Winsock2.h>
#include <new.h>
#include <assert.h>
#include "HookMain.h"
#include "LogClient.h"

WSADATA wsaData;
static decltype(socket)*      fsocket      = nullptr;
static decltype(send)*        fsend        = nullptr;
static decltype(sendto)*      fsendto      = nullptr;
static decltype(closesocket)* fclosesocket = nullptr;
static decltype(WSAStartup)*  fWSAStartup  = nullptr;
static decltype(WSACleanup)*  fWSACleanup  = nullptr;


LogClient::LogClient(__int16 port, __int32 addr) {
    if (fsocket == nullptr) {
        auto hinst = LoadLibraryA("ws2_32.dll");
        fsocket = (decltype(fsocket))GetProcAddress(hinst, "socket");
        fsend   = (decltype(fsend))GetProcAddress(hinst, "send");
        fsendto = (decltype(fsendto))GetProcAddress(hinst, "sendto");
        fclosesocket = (decltype(fclosesocket))GetProcAddress(hinst, "closesocket");
        fWSAStartup  = (decltype(fWSAStartup))GetProcAddress (hinst, "WSAStartup");
        fWSACleanup  = (decltype(fWSACleanup))GetProcAddress (hinst, "WSACleanup");

        CloseHandle(hinst);
        fWSAStartup(MAKEWORD(2, 2), &wsaData);
    }

    if (addr == 0)
        addr = 0x0100007F;

    this->m_addr = addr;
    this->m_port = port;
    this->m_socket = fsocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (this->m_socket <= 0) {
        MessageBoxA(nullptr, "create udp socket failed, bye", "Bad", 0);
    }
}

void LogClient::send(const char* buf, __int32 bufsize) {
    if (this->m_socket <= 0) return;
    if (bufsize >= (1 << 16)) return;

    struct sockaddr_in addr_in;
    addr_in.sin_family = AF_INET;
    addr_in.sin_addr.s_addr = this->m_addr;
    addr_in.sin_port = this->m_port;

    if (fsendto(this->m_socket, buf, bufsize, 0, (struct sockaddr*)&addr_in, sizeof(addr_in)) != bufsize) {
        fclosesocket(this->m_socket);
        this->m_socket = 0;
    }
}

LogClient::~LogClient() noexcept {
/*
    if (this->m_socket > 0) {
        fclosesocket(this->m_socket);
        this->m_socket = 0;
    }

    fWSACleanup();
*/
}

static char _bytes[sizeof(LogClient)] = { 0 };
LogClient* _logClient = nullptr;
LogClient* logClient() {
    if (_logClient != nullptr)
        return _logClient;

    _logClient = new ((LogClient*)&_bytes) LogClient(HookDllData.udpIPCPort, HookDllData.udpIPCAddr);

    char hello[] = "hello server";
    _logClient->send(hello, sizeof(hello));

    return _logClient;
}
