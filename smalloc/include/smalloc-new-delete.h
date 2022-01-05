#ifndef _SMALLOC_NEW_DELETE_H_
#define _SMALLOC_NEW_DELETE_H_

#include "./smalloc.h"
#include <new.h>


extern void* operator new(size_t size) noexcept { return smalloc(size); }
extern void* operator new[](size_t size) noexcept { return smalloc(size); }

extern void operator delete(void* ptr) noexcept { sfree(ptr); }
extern void operator delete[](void* ptr) noexcept { sfree(ptr); }

#endif // _SMALLOC_NEW_DELETE_H_