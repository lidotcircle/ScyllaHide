#include "scylla/splug.h"

namespace scylla {

SPlug::SPlug(ScyllaContextPtr context): m_context(context) {}

ScyllaContextPtr SPlug::context() {
    return m_context;
}

const ScyllaContextPtr SPlug::context() const {
    return m_context;
}

SPlug::~SPlug() {}

void SPlug::undo() {}

} // namespace scylla