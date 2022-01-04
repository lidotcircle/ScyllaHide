#include "scylla/charybdis.h"
#include "scylla/context_base.h"
#include "scylla/splug/log_server.h"
#include "scylla/splug/dll_injector.h"
#include "scylla/splug/inline_hook.h"
#include "scylla/splug/key_value.h"
#include "scylla/splug/exchange.h"
#include "scylla/splug/peb_patch.h"
#include <yaml-cpp/yaml.h>
#include <stdexcept>
using namespace std;
using namespace scylla;


Charybdis::Charybdis(WinProcess_t process)
{
    m_context = make_shared<ScyllaContextBase>(process);
    m_splug_manager = make_unique<SPlugManager>(this->m_context);

    m_splug_manager->add_splug("logger",      [](auto ctx) { return make_unique<SPlugLogServer>(ctx); });
    m_splug_manager->add_splug("dllInjector", [](auto ctx) { return make_unique<SPlugDLLInjector>(ctx); });
    m_splug_manager->add_splug("keyValue",    [](auto ctx) { return make_unique<SPlugKeyValue>(ctx); });
    m_splug_manager->add_splug("inlineHook",  [](auto ctx) { return make_unique<SPlugInlineHook>(ctx); });
    m_splug_manager->add_splug("exchange",    [](auto ctx) { return make_unique<SPlugExchange>(ctx); });
    m_splug_manager->add_splug("pebPatch",    [](auto ctx) { return make_unique<SPlugPebPatch>(ctx); });
}

void Charybdis::doit_string(const string& yaml_string) {
    auto node = YAML::Load(yaml_string);
    this->doit(node);

}
void Charybdis::doit_file(const string& filename) {
    auto node = YAML::LoadFile(filename);
    this->doit(node);
}
void Charybdis::doit(const YAML::Node& node) {
    if (!node.IsMap())
        throw std::runtime_error("Charybdis::doit(): node is not a map");
    this->m_splug_manager->doit(node);
}

void Charybdis::undo() {
    this->m_splug_manager->undo();
}

std::shared_ptr<SPlugConfig> Charybdis::get_splug_config() {
    return this->m_context->splug_config();
}
const std::shared_ptr<SPlugConfig> Charybdis::get_splug_config() const {
    return this->m_context->splug_config();
}
void Charybdis::set_splug_config(std::shared_ptr<SPlugConfig> config) {
    this->m_context->set_splug_config(config);
}

void Charybdis::set_log_client(std::shared_ptr<LogClient> log_client) {
    this->m_context->set_log_client(log_client);
}