#if defined(_WIN32) || defined(_WIN64)
#include "process/memory_map_win_page.h"
#include "utils.hpp"
#include "str_utils.h"
#include <stdexcept>
#include <Windows.h>
#include <string>
using namespace std;

#define PREFERED_CACHE_SIZE 4096
#define MIN_AB(a, b) ((a) < (b) ? (a) : (b))


static string integer2hexstr(int64_t val) {
    string ret;
    char buf[16];
    snprintf(buf, sizeof(buf), "%llx", val);
    ret = buf;
    return ret;
}

static string addr2hexstr(void* addr) {
    return integer2hexstr(reinterpret_cast<int64_t>(addr));
}

MemoryMapWinPage::MemoryMapWinPage(ProcessHandle handle, void* base, size_t size, bool direct_write):
    process_handle(handle), baseaddress(reinterpret_cast<addr_t>(base)), map_size(size),
    cache(new char[PREFERED_CACHE_SIZE]), cache_size(0), cache_offset(size), direct_write(direct_write), write_dirty(false)
{
}

MemoryMapWinPage::~MemoryMapWinPage()
{
    if (cache)
        delete[] cache;
}

MemoryMapWinPage::addr_t MemoryMapWinPage::baseaddr() const
{
    return this->baseaddress;
}
    
size_t MemoryMapWinPage::size() const
{
    return this->map_size;
}

static bool page_readable(int prot)
{
    return (prot & PAGE_READONLY) || (prot & PAGE_READWRITE) || 
           (prot & PAGE_EXECUTE_READ) || (prot & PAGE_EXECUTE_READWRITE) ||
           (prot & PAGE_EXECUTE_WRITECOPY) || (prot & PAGE_WRITECOPY);
}

static bool page_writable(int prot) {
    return (prot & PAGE_READWRITE) || (prot & PAGE_EXECUTE_READWRITE) ||
           (prot & PAGE_EXECUTE_WRITECOPY) || (prot & PAGE_WRITECOPY);
}

static bool page_executable(int prot) {
    return (prot & PAGE_EXECUTE) || (prot & PAGE_EXECUTE_READ) ||
           (prot & PAGE_EXECUTE_READWRITE) || (prot & PAGE_EXECUTE_WRITECOPY);
}

char MemoryMapWinPage::get_at(addr_t offset) const {
    if (offset >= map_size)
        throw out_of_range(
            strformat("MemoryMapWinPage::get_at(0x%lx): offset out of range", offset));

    auto _this = const_cast<MemoryMapWinPage*>(this);

    auto base = this->baseaddress;
    auto addr = reinterpret_cast<void*>(base + offset);

    if (cache_offset <= offset && offset < cache_offset + cache_size) {
        return cache[offset - cache_offset];
    }

    if (this->write_dirty)
        _this->flush();

    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQueryEx(*_this->process_handle.get(), addr, &mbi, sizeof(mbi))) {
        throw runtime_error("MemoryMapWinPage::get_at(): VirtualQueryEx failed");
    }
    DWORD alloc_protect = mbi.AllocationProtect, old_protect;
    bool readable = page_readable(mbi.Protect);
    const size_t kcache_size = MIN_AB(PREFERED_CACHE_SIZE, map_size - offset);

    if (!readable && !VirtualProtectEx(*this->process_handle.get(), addr, kcache_size, alloc_protect, &old_protect)) {
        throw runtime_error("MemoryMapWinPage::get_at(): VirtualProtectEx failed: 0x" + addr2hexstr(addr));
    }

    auto cleanProtectEx = defer([&]() {
        if (!readable)
            VirtualProtectEx(*this->process_handle.get(), addr, kcache_size, old_protect, &old_protect);
    });

    SIZE_T n = 0;
    if (!ReadProcessMemory(*this->process_handle.get(), addr, cache, kcache_size, &n) || n != kcache_size) {
        throw runtime_error("MemoryMapWinPage::get_at(): ReadProcessMemory failed at: 0x" + addr2hexstr(addr) + 
                            ", region base: 0x" + integer2hexstr(base) + " NumOfBytesRead = " + to_string(n) +
                            ", " + GetLastErrorAsString());
    }

    _this->cache_size = n;
    _this->cache_offset = offset;
    return cache[offset - cache_offset];
}

void MemoryMapWinPage::set_at(addr_t offset, char value) {
    if (offset >= map_size)
        throw out_of_range(
            strformat("MemoryMapWinPage::set_at(%lx, %c)[map_size = %lx]: offset out of range", offset, value, map_size));

    auto addr = reinterpret_cast<void*>(this->baseaddress + offset);
    if (this->direct_write) {
        DWORD old_protect;
        if (!VirtualProtectEx(*this->process_handle.get(), addr, 1, PAGE_READWRITE, &old_protect))
        {
            throw runtime_error("MemoryMapWinPage::set_at(): VirtualProtectEx failed: 0x" + addr2hexstr(addr));
        }
        auto d1 = defer([&]() { VirtualProtectEx(*this->process_handle.get(), addr, 1, old_protect, &old_protect); });

        if (!WriteProcessMemory(*this->process_handle.get(), addr, &value, 1, nullptr))
            throw runtime_error("MemoryMapWinPage::set_at(): WriteProcessMemory failed");

        return;
    }

    if (offset < this->cache_offset || offset >= this->cache_offset + cache_size)
        this->get_at(offset);

    this->cache[offset - this->cache_offset] = value;
    this->write_dirty = true;
}

void MemoryMapWinPage::flush() {
    if (!this->write_dirty) {
        this->cache_offset = this->map_size;
        return;
    }

    auto base = baseaddress;
    auto addr = reinterpret_cast<void*>(base + this->cache_offset);

    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQueryEx(*this->process_handle.get(), addr, &mbi, sizeof(mbi))) {
        throw runtime_error("VirtualQueryEx failed");
    }
    DWORD alloc_protect = mbi.AllocationProtect, old_protect;
    bool writable = page_writable(mbi.Protect);

    if (!writable && !VirtualProtectEx(*this->process_handle.get(), addr, this->cache_size, PAGE_EXECUTE_READWRITE, &old_protect))
    {
        throw runtime_error("VirtualProtectEx failed");
    }

    auto clearProtectEx = defer([&]() {
        if (!writable)
            VirtualProtectEx(*this->process_handle.get(), addr, this->cache_size, old_protect, &old_protect);
        this->cache_offset = this->map_size;
        this->write_dirty = false;
    });

    if (!WriteProcessMemory(*this->process_handle.get(), addr, this->cache, cache_size, nullptr)) {
        throw runtime_error("WriteProcessMemory failed");
    }
}

#endif // _WIN32 || _WIN64