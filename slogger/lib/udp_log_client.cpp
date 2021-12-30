#include "logger/udp_log_client.h"
#include <Winsock2.h>
#include <WinUser.h>

static WSADATA wsaData;
static decltype(socket)*      fsocket      = nullptr;
static decltype(send)*        fsend        = nullptr;
static decltype(sendto)*      fsendto      = nullptr;
static decltype(closesocket)* fclosesocket = nullptr;
static decltype(WSAStartup)*  fWSAStartup  = nullptr;
static decltype(WSACleanup)*  fWSACleanup  = nullptr;

static decltype(MessageBoxA)* fMessageBoxA = nullptr;
static int MessageBoxN(HWND wnd, LPCSTR text, LPCSTR caption, UINT type)
{
    if (!fMessageBoxA)
        fMessageBoxA = (decltype(MessageBoxA)*)GetProcAddress(LoadLibraryA("user32.dll"), "MessageBoxA");

    if (fMessageBoxA)
        return fMessageBoxA(wnd, text, caption, type);
    return 0;
}

UDPLogClient::UDPLogClient(uint16_t port, uint32_t addr)
    : m_socket(0)
    , m_port(port)
    , m_addr(addr)
{
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

    if (this->m_socket <= 0)
        MessageBoxN(nullptr, "create udp socket failed, bye", "Bad", 0);
}

void UDPLogClient::send(const char* buf, uint16_t bufsize) {
    if (this->m_socket <= 0) return;

    struct sockaddr_in addr_in;
    addr_in.sin_family = AF_INET;
    addr_in.sin_addr.s_addr = this->m_addr;
    addr_in.sin_port = this->m_port;

    if (fsendto(this->m_socket, buf, bufsize, 0, (struct sockaddr*)&addr_in, sizeof(addr_in)) != bufsize) {
        fclosesocket(this->m_socket);
        this->m_socket = 0;
    }
}

UDPLogClient::~UDPLogClient() {
    if (this->m_socket > 0)
        fclosesocket(this->m_socket);
}