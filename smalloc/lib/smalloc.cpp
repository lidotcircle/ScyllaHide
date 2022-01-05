#include "smalloc.h"
#include <Windows.h>

#define __abort(msg) (void)0


struct page_header {
    size_t m_size;
    size_t m_used;
    page_header* m_next;
};

struct slot_header {
    size_t m_size;
    page_header* m_page;
    bool   m_free;
    void*  m_ptr;
};
constexpr size_t slot_header_size = offsetof(slot_header, m_ptr);

static void* os_alloc_page(size_t size)
{
    auto ptr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (ptr == NULL)
        __abort("VirtualAlloc failed");
    return ptr;
}

static void os_free_page(void* ptr)
{
    if (!VirtualFree(ptr, 0, MEM_RELEASE))
        __abort("VirtualFree failed");
}

static size_t system_pagesize = 0;
static size_t proper_page_size(size_t request)
{
    if (system_pagesize == 0)
    {
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        system_pagesize = si.dwPageSize;
    }
    return (request + system_pagesize - 1) & ~(system_pagesize - 1);
}

static size_t aligned_size(size_t size, size_t alignment)
{
    return (size + alignment - 1) & ~(alignment - 1);
}

static page_header* alloc_page(size_t size)
{
    auto nsize = proper_page_size(size + 0x1000);
    auto _page = os_alloc_page(nsize);
    auto page = static_cast<page_header*>(_page);
    if (page == NULL)
        return NULL;
    page->m_size = nsize;
    page->m_used = sizeof(page_header);
    page->m_next = NULL;

    auto _n = reinterpret_cast<size_t>(page) + sizeof(page_header);
    auto first_slot = reinterpret_cast<slot_header*>(_n);
    first_slot->m_free = true;
    first_slot->m_page = page;
    first_slot->m_size = nsize - sizeof(page_header);
    first_slot->m_ptr  = &first_slot->m_ptr;

    return page;
}

static page_header* page_list = nullptr;
static void adjust_slot(slot_header* sh, size_t size) {
    size = aligned_size(size, sizeof(void*));
    if (sh->m_size <= size + slot_header_size + sizeof(void*))
        return;
    
    auto _n = reinterpret_cast<size_t>(sh) + size;
    auto nsh = reinterpret_cast<slot_header*>(_n);
    nsh->m_free = true;
    nsh->m_page = sh->m_page;
    nsh->m_size = sh->m_size - size - slot_header_size;
    nsh->m_ptr  = &nsh->m_ptr;

    sh->m_size = size;
}

static void* alloc_slot_from_page(page_header* page, size_t size)
{
    auto _n = reinterpret_cast<size_t>(page) + sizeof(page_header);
    auto slot = reinterpret_cast<slot_header*>(_n);
    auto page_end = reinterpret_cast<size_t>(page) + page->m_size;
    size += slot_header_size;

    do {
        if (slot->m_free && slot->m_size >= size)
        {
            adjust_slot(slot, size);
            slot->m_free = false;
            slot->m_page->m_used += size;
            return &slot->m_ptr;
        }
        slot = reinterpret_cast<slot_header*>(reinterpret_cast<size_t>(slot) + slot->m_size);
    } while (reinterpret_cast<size_t>(slot) < page_end);

    return nullptr;
}

static void* alloc_slot(size_t size)
{
    auto ppage = &page_list;
    while (*ppage != nullptr)
    {
        auto s = alloc_slot_from_page(*ppage, size);
        if (s != nullptr)
            return s;

        ppage = &(*ppage)->m_next;
    }

    auto page = alloc_page(size);
    *ppage = page;

    return alloc_slot_from_page(page, size);
}

static void merge_slot(slot_header* sh)
{
    auto _n = reinterpret_cast<size_t>(sh) + sh->m_size;
    if (_n >= sh->m_page->m_size + reinterpret_cast<size_t>(sh->m_page))
        return;

    auto nsh = reinterpret_cast<slot_header*>(_n);
    if (nsh->m_free)
        sh->m_size += nsh->m_size;
}

extern "C" void* smalloc(size_t size) {
    auto ptr = alloc_slot(size);
    if (ptr == nullptr)
        __abort("smalloc failed");
    return ptr;
}

extern "C" void* smalloc_aligned(size_t size, size_t alignment) {
    __abort("not implemented");
    return nullptr;
}

extern "C" void  sfree(void* ptr) {
    auto sh = reinterpret_cast<slot_header*>(reinterpret_cast<size_t>(ptr) - slot_header_size);
    if (sh->m_free)
        __abort("invalid sfree");

    sh->m_free = true;
    sh->m_page->m_used -= sh->m_size;
    merge_slot(sh);
}