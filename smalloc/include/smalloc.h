#ifndef _SMALLOC_H_
#define _SMALLOC_H_

#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


void* smalloc(size_t size);
void  sfree(void* ptr);

void* smalloc_aligned(size_t size, size_t alignment);


#ifdef __cplusplus
}
#endif

#endif // _SMALLOC_H_