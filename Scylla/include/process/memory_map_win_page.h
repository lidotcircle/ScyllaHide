#ifndef _MEMORY_MAP_WIN_PAGE_H_
#define _MEMORY_MAP_WIN_PAGE_H_

#include "memory_map.h"
#include <memory>
#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#else
typedef int HANDLE;
#endif // defined(_WIN32) || defined(_WIN64)


class MemoryMapWinPage : public MemoryMap
{
public:
    using ProcessHandle = std::shared_ptr<HANDLE>;

private:
    ProcessHandle process_handle;
    addr_t baseaddress;
    size_t map_size;
    char* cache;
    size_t cache_offset;
    size_t cache_size;
    bool direct_write;
    bool write_dirty;

public:
    MemoryMapWinPage(ProcessHandle process_handle, void* baseaddress, size_t map_size, bool direct_write);

    virtual addr_t baseaddr() const override;
    virtual size_t size() const override;

    virtual char get_at(addr_t index) const override;
    virtual void set_at(addr_t index, char value) override;

    virtual void flush() override;
    ~MemoryMapWinPage() override;
};

#endif // _MEMORY_MAP_WIN_PAGE_H_