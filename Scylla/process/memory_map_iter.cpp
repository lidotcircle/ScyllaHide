#include "process/memory_map_iter.h"
#include "process/memory_map.h"
#include <stdexcept>
using namespace std;

MemoryMapIter::MemoryMapIter(MemoryMap* map, size_t index): map(map),  index(index)
{
}

MemoryMapIter::~MemoryMapIter() {}

MemoryMapIter& MemoryMapIter::operator++() {
    if (index >= map->size()) {
        throw out_of_range("ProcessMapIter::operator++");
    }
    index++;
    return *this;
}

MemoryMapIter MemoryMapIter::operator++(int) {
    MemoryMapIter tmp(*this);
    operator++();
    return tmp;
}

MemoryMapIter& MemoryMapIter::operator--() {
    if (index == 0) {
        throw out_of_range("ProcessMapIter::operator--");
    }
    index--;
    return *this;
}

MemoryMapIter MemoryMapIter::operator--(int) {
    MemoryMapIter tmp(*this);
    operator--();
    return tmp;
}

MemoryMapIter& MemoryMapIter::operator+=(int n) {
    if (n < 0)
        return operator-=(-n);

    index += n;
    if (index > map->size()) {
        throw out_of_range("ProcessMapIter::operator+=");
    }
    return *this;
}

MemoryMapIter& MemoryMapIter::operator-=(int n) {
    if (n < 0)
        return this->operator+=(-n);

    if (index < n || index - n > this->map->size()) {
        throw out_of_range("ProcessMapIter::operator-=");
    }
    index -= n;
    return *this;
}

MemoryMapIter MemoryMapIter::operator+(int n) const {
    if (n < 0)
        return this->operator-(-n);

    MemoryMapIter tmp(*this);
    if (tmp.index + n > map->size())
        throw out_of_range("ProcessMapIter::operator+");
    tmp.index += n;
    return tmp;
}

MemoryMapIter MemoryMapIter::operator-(int n) const {
    if (n < 0)
        return this->operator+(-n);

    MemoryMapIter tmp(*this);
    if (tmp.index < n)
        throw out_of_range("ProcessMapIter::operator-");
    tmp.index -= n;
    return tmp;
}

MemoryMapIter::difference_type MemoryMapIter::operator-(const MemoryMapIter &other) const {
    if (this->map != other.map)
        throw invalid_argument("ProcessMapIter::operator-");
    return index - other.index;
}

bool MemoryMapIter::operator==(const MemoryMapIter& other) const {
    return this->map == other.map &&  index == other.index;
}

bool MemoryMapIter::operator!=(const MemoryMapIter& other) const {
    return !operator==(other);
}

MemoryValueRef MemoryMapIter::operator*() {
    return MemoryValueRef(map, index);
}
