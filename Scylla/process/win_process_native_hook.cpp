#include "pe_header.h"
#include "process/win_process_native.h"
#include "process/memory_map_win_page.h"
#include "process/memory_map_module.h"
#include "process/memory_map_section.h"
#include <distorm/distorm.h>
#include <stdexcept>
#include <memory>
#include <vector>
#include <algorithm>
#include <iostream>
#include <assert.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <Windows.h>
#include "utils.hpp"
using namespace std;

using hook_t = typename WinProcessNative::hook_t;
using addr_t = typename WinProcessNative::addr_t;
#ifdef _WIN64
static _DecodeType DecodingType = Decode64Bits;
const int minDetourLen = 2 + sizeof(DWORD)+sizeof(DWORD_PTR) + 1; //8+4+2+1=15
#else
static _DecodeType DecodingType = Decode32Bits;
const int minDetourLen = sizeof(DWORD) + 1;
const int detourLenWow64FarJmp = 1 + sizeof(DWORD) + sizeof(USHORT); // EA far jmp
#endif
#define MAXIUM_INSTRUCTION_SIZE (15) //maximum instruction size == 15

static vector<char> WriteJumper(void* lpbFrom, void* lpbTo, bool prefixNop)
{
    vector<char> vb;
#ifdef _WIN64
    if (prefixNop)
        vb.push_back(0x90);

    vb.push_back(0xFF);
    vb.push_back(0x25);
    vb.push_back(0x00);
    vb.push_back(0x00);
    DWORD_PTR dwRel = (DWORD_PTR)lpbTo;
    for (size_t i=0;i<sizeof(dwRel);i++)
    {
        vb.push_back((char)(dwRel & 0xFF));
        dwRel >>= 8;
    }
#else
    vb.push_back((char)0xE9);
    DWORD addr = (DWORD)lpbTo - (DWORD)lpbFrom - 5;
    for (size_t i=0;i<sizeof(addr);i++) {
        vb.push_back((char)(addr & 0xFF));
        addr >>= 8;
    }
#endif

    return vb;
}

static int LengthDisassemble(LPVOID DisassmAddress)
{
    unsigned int DecodedInstructionsCount = 0;
    _CodeInfo decomposerCi = { 0 };
    _DInst decomposerResult[1] = { 0 };

    decomposerCi.code = (BYTE *)DisassmAddress;
    decomposerCi.codeLen = MAXIUM_INSTRUCTION_SIZE;
    decomposerCi.dt = DecodingType;
    decomposerCi.codeOffset = (LONG_PTR)DisassmAddress;

    if (distorm_decompose(&decomposerCi, decomposerResult, _countof(decomposerResult), &DecodedInstructionsCount) != DECRES_INPUTERR)
    {
        if (decomposerResult[0].flags != FLAG_NOT_DECODABLE)
        {
            return decomposerResult[0].size;
        }
    }

    return -1; //this is dangerous
}

static int GetDetourLen(const void * lpStart, const int minSize)
{
    int totalLen = 0;
    unsigned char * lpDataPos = (unsigned char *)lpStart;

    while (totalLen < minSize)
    {
        int len = (int)LengthDisassemble((void *)lpDataPos);
        if (len < 1) //len < 1 will cause infinite loops
            len = 1;
        lpDataPos += len;
        totalLen += len;
    }

    return totalLen;
}


class WinHookHandle : public HookHandle {
private:
    void* trampline_addr;
    void* original_addr;
    vector<char> original_detour;

public:
    WinHookHandle(void* original, void* trampline_addr, const vector<char>& original_detour) :
        original_addr(original), trampline_addr(trampline_addr), original_detour(original_detour) {}
    virtual ~WinHookHandle() override = default;

    virtual void* trampoline() override { return trampline_addr; }
    void* original() { return original_addr; }
    size_t detourLen() { return original_detour.size(); }
    const vector<char>& originalDetour() { return original_detour; }
};

hook_t WinProcessNative::hook(addr_t original, addr_t hook) {
    if (!this->process_handle)
        return nullptr;
    
    auto originalBytes = this->read(original, MAXIUM_INSTRUCTION_SIZE + minDetourLen - 1);
    if (originalBytes.empty())
        return nullptr;

    auto detourLen = GetDetourLen(originalBytes.data(), minDetourLen);

    auto trampoline = this->malloc(detourLen + minDetourLen, 1, PAGE_EXECUTE_READWRITE);
    if (!trampoline)
        return nullptr;
    bool clean_trampoline = false;
    defer([&]() { if (clean_trampoline) this->free(trampoline); });

    vector<char> trampoline_data(originalBytes.begin(), originalBytes.begin() + detourLen);
    auto trampoline_detour = reinterpret_cast<addr_t>(trampoline) + detourLen;
    auto detourx = WriteJumper(reinterpret_cast<void*>(trampoline_detour),
                               reinterpret_cast<void*>(original + detourLen), false);
    trampoline_data.insert(trampoline_data.end(), detourx.begin(), detourx.end());

    if (!this->write(trampoline, trampoline_data)) {
        clean_trampoline = true;
        return nullptr;
    }

    auto detouro = WriteJumper(reinterpret_cast<void*>(original), reinterpret_cast<void*>(hook), false);
    auto original_detour = vector<char>(originalBytes.begin(), originalBytes.begin() + detourLen);
    if (!this->write(original, detouro)) {
        clean_trampoline = true;
        return nullptr;
    }

    return make_unique<WinHookHandle>(reinterpret_cast<void*>(original), trampoline, original_detour);
}

bool  WinProcessNative::unhook(hook_t hook) {
    if (!hook || !this->process_handle)
        return false;
    
    auto h1 = hook.get();
    auto h2 = dynamic_cast<WinHookHandle*>(h1);
    if (!h2)
        return false;
    
    auto original = h2->original();
    auto trampoline = h2->trampoline();
    auto detourLen = h2->detourLen();

    if (!this->write(original, h2->originalDetour()))
        return false;
    
    this->free(trampoline);
    return true;
}