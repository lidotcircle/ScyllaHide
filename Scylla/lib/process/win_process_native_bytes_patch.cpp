#include "process/win_process_native.h"
#include <vector>
#include <stdexcept>
using namespace std;

using addr_t = typename WinProcessNative::addr_t;
using patch_t = typename WinProcessNative::patch_t;


class NPatchHandle: public WinProcessNative::PatchHandle {
private:
    vector<char> m_original_bytes;
    addr_t m_address;

public:
    NPatchHandle(addr_t address, const vector<char>& original_bytes):
        m_address(address), m_original_bytes(original_bytes) {}
    virtual ~NPatchHandle() override = default;

    virtual addr_t addr() const override { return m_address; }
    virtual const std::vector<char>& original_data() const override { return m_original_bytes; }
};

patch_t WinProcessNative::patch(addr_t addr, const std::vector<char>& data)
{
    auto origin = this->read(addr, data.size());
    if (!this->write(addr, data))
        throw std::runtime_error("patch failed: failed to write");
    
    return std::unique_ptr<PatchHandle>(new NPatchHandle(addr, origin));
}
patch_t WinProcessNative::patch(addr_t addr, uint8_t val)
{
    return patch(addr, vector<char>{(char)val});
}
patch_t WinProcessNative::patch(addr_t addr, uint16_t val)
{
    return patch(addr, vector<char>{(char)(val & 0xff), (char)((val >> 8) & 0xff)});
}
patch_t WinProcessNative::patch(addr_t addr, uint32_t val)
{
    return patch(addr, vector<char>{(char)(val & 0xff), (char)((val >> 8) & 0xff), 
                                    (char)((val >> 16) & 0xff), (char)((val >> 24) & 0xff)});
}
patch_t WinProcessNative::patch(addr_t addr, uint64_t val)
{
    return patch(addr, vector<char>{(char)(val & 0xff), (char)((val >> 8) & 0xff),
                                    (char)((val >> 16) & 0xff), (char)((val >> 24) & 0xff),
                                    (char)((val >> 32) & 0xff), (char)((val >> 40) & 0xff),
                                    (char)((val >> 48) & 0xff), (char)((val >> 56) & 0xff)});
}
void WinProcessNative::unpatch(patch_t patch)
{
    if (!this->write(patch->addr(), patch->original_data()))
        throw std::runtime_error("unpatch failed: failed to write");
}
