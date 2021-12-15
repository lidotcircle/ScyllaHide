#ifndef _MEMORY_VALUE_REF_H_
#define _MEMORY_VALUE_REF_H_

#include <stdlib.h>


class MemIndexable;

class MemoryValueRef {
private:
    MemIndexable *mem;
    int index;

public:
    MemoryValueRef(MemIndexable *mem, size_t index);
    operator char() const;
    MemoryValueRef& operator=(char value);
};

#endif // _MEMORY_VALUE_REF_H_