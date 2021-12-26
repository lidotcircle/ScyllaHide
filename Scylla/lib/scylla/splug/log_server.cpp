#include "scylla/splug/log_server.h"
#include "logger/udp_console_log_server.h"
#include <stdexcept>
#include <thread>
using namespace std;
using namespace scylla;

static vector<string> split_str(const string& s, char delim) {
    vector<string> elems;
    stringstream ss(s);
    string item;
    while (getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}
static uint32_t resolve_dot_ipv4(const string& dotip) {
    auto parts = split_str(dotip, '.');
    if (parts.size() != 4) {
        throw runtime_error("invalid ipv4 address");
    }
    uint32_t ip = 0;
    for (auto& part : parts) {
        ip = (ip << 8) | stoi(part);
    }
    return ip;
}

namespace scylla {

SPlugLogServer::SPlugLogServer(ScyllaContextPtr context) : SPlug(context) {}

SPlugLogServer::~SPlugLogServer() {}

void SPlugLogServer::doit(const YAML::Node& node) {
    if (!node.IsMap())
        throw std::runtime_error("SPlugLogServer::doit: node is not a map");

    if (node["disable"].as<bool>(false))
        return;

    auto port     = node["udp_port"].as<uint16_t>(0);
    auto addr_str = node["udp_addr"].as<string>("localhost");
    if (addr_str == "localhost")
        addr_str = "127.0.0.1";

    auto addr = resolve_dot_ipv4(addr_str);
    auto server = make_unique<UDPConsoleLogServer>(htons(port), htonl(addr));

    auto ctx = this->context();
    auto exch = ctx->exchange();
    exch.set_udp_port(server->GetPort());
    exch.set_udp_addr(server->GetAddr());
    this->m_log_server = move(server);

    this->m_log_server_poll_thread = make_unique<thread>([this] {
        this->m_log_server->poll();
    });
}

void SPlugLogServer::undo() {
    if (this->m_log_server)
        this->m_log_server->stop();

    if (this->m_log_server_poll_thread) {
        this->m_log_server_poll_thread->join();
        this->m_log_server_poll_thread.reset();
    }
}

} // namespace scylla