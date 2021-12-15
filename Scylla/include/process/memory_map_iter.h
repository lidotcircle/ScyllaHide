#ifndef _MEMORY_MAP_ITER_H_
#define _MEMORY_MAP_ITER_H_

#include "memory_value_ref.h"
#include <iterator>


class MemoryMap;

class MemoryMapIter {
public:
    using difference_type = std::ptrdiff_t;
    using value_type = char;
    using pointer = value_type*;
    using reference = value_type&;
    using iterator_category = std::forward_iterator_tag;

private:
    MemoryMap *map;
    size_t index;

public:
    MemoryMapIter(MemoryMap *map, size_t);
    ~MemoryMapIter();

    MemoryMapIter &operator++();
    MemoryMapIter operator++(int);
    MemoryMapIter &operator--();
    MemoryMapIter operator--(int);

    MemoryMapIter &operator+=(int n);
    MemoryMapIter &operator-=(int n);

    MemoryMapIter operator+(int n) const;
    MemoryMapIter operator-(int n) const;

    difference_type operator-(const MemoryMapIter &other) const;

    bool operator==(const MemoryMapIter &other) const;
    bool operator!=(const MemoryMapIter &other) const;

    // char operator*();
    MemoryValueRef operator*();
};

#endif // _MEMORY_MAP_ITER_H_