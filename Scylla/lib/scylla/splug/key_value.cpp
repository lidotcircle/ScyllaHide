#include "scylla/splug/key_value.h"
#include <stdexcept>
using namespace std;
using namespace scylla;


namespace scylla {

SPlugKeyValue::SPlugKeyValue(ScyllaContextPtr context) : SPlug(context) {}

SPlugKeyValue::~SPlugKeyValue() {}

void SPlugKeyValue::doit(const YAML::Node& node) {
    if (!node.IsMap())
        throw std::runtime_error("SPlugKeyValue::doit: node is not a map");
    
    auto ctx = this->context();
    auto& exch = ctx->exchange();
    
    for (auto it = node.begin(); it != node.end(); ++it) {
        string key = it->first.as<string>();
        string value = it->second.as<string>();
        exch.add_key_value(key, value);
    }
}

void SPlugKeyValue::undo() {}

} // namespace scylla