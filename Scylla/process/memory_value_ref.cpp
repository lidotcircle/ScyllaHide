#include "process/memory_value_ref.h"
#include "process/mem_indexable.h"
#include <stdexcept>
using namespace std;


MemoryValueRef::MemoryValueRef(MemIndexable* mem, size_t index): mem(mem), index(index)
{
}

MemoryValueRef::operator char() const {
    return this->mem->get_at(index);
}

MemoryValueRef& MemoryValueRef::operator=(char value) {
    this->mem->set_at(this->index, value);
    return *this;
}

