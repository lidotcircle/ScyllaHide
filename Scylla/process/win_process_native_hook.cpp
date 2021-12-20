#include "pe_header.h"
#include "process/win_process_native.h"
#include "process/memory_map_win_page.h"
#include "process/memory_map_module.h"
#include "process/memory_map_section.h"
#include <distorm/distorm.h>
#include <distorm/mnemonics.h>
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

static vector<char> RedirectRelativeJmp(void* old_addr, void* new_addr, const vector<char>& instrucs) {
    _CodeInfo decomposerCi = { 0 };
    decomposerCi.code = (const uint8_t*)instrucs.data();
    decomposerCi.codeLen = instrucs.size();
    decomposerCi.codeOffset = (LONG_PTR)old_addr;
    decomposerCi.dt = DecodingType;
    shared_ptr<_DInst> dresult(new _DInst[instrucs.size()], std::default_delete<_DInst[]>());
    size_t DecodedInstructionsCount = 0;

    if (!distorm_decompose(&decomposerCi, dresult.get(), instrucs.size(), &DecodedInstructionsCount))
        return vector<char>();
    
    vector<char> new_instrucs;
    size_t cn = 0;
    _DInst dinst = dinst = dresult.get()[0];
    for (size_t i = 0; i < DecodedInstructionsCount;
         cn += dinst.size, i++, dinst = dresult.get()[i])
    {
        if (dinst.ops[0].type != O_PC || dinst.opcode == I_JCXZ || dinst.opcode == I_JECXZ) {
            new_instrucs.insert(new_instrucs.end(), instrucs.begin() + cn, instrucs.begin() + cn + dinst.size);
            continue;
        }

        // rel8 and target in this block
        if (dinst.size == 2) {
            auto dest = dinst.imm.addr + cn + 2;
            if (dest >= 0 && dest < (decltype(dest))instrucs.size()) {
                new_instrucs.insert(new_instrucs.end(), instrucs.begin() + cn, instrucs.begin() + cn + dinst.size);
                continue;
            }
        }

        auto a1 = reinterpret_cast<uintptr_t>(new_addr) + new_instrucs.size();
        auto a2 = reinterpret_cast<uintptr_t>(old_addr) + cn;
        DWORD dest = (DWORD)dinst.imm.addr + a2 - a1;

        // rel32
        if (dinst.size == 5 || dinst.size == 6) {
            char instr[6] = { 0 };
            instr[0]= instrucs[cn];
            instr[1]= instrucs[cn + 1];
            *(DWORD*)&instr[dinst.size - 4] = dest;
            new_instrucs.insert(new_instrucs.end(), instr, instr + dinst.size);
            continue;
        }

        // 2bytes  jcc rel8 / jmp rel8
        if (dinst.opcode == I_JMP) {
            dest -= 3;
            new_instrucs.push_back((unsigned char)0xE9);
        } else {
            dest -= 4;
            new_instrucs.push_back((unsigned char)0x0F);
            new_instrucs.push_back((uint8_t)instrucs[cn] + 0x10);
        }
        char instr[4] = { 0 };
        *(DWORD*)&instr[1] = dest;
        new_instrucs.insert(new_instrucs.end(), instr, instr + 4);
    }

    return new_instrucs;
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

    auto trampoline = this->malloc((detourLen + minDetourLen) * 3, 1, PAGE_EXECUTE_READWRITE);
    if (!trampoline)
        return nullptr;
    bool clean_trampoline = false;
    defer([&]() { if (clean_trampoline) this->free(trampoline); });

    vector<char> detour_data(originalBytes.begin(), originalBytes.begin() + detourLen);
    auto trampoline_data = RedirectRelativeJmp(reinterpret_cast<void*>(original), trampoline, detour_data);

    auto trampoline_detour = reinterpret_cast<addr_t>(trampoline) + detourLen;
    auto detourx = WriteJumper(reinterpret_cast<void*>(trampoline_detour),
                               reinterpret_cast<void*>(original + detourLen), false);
    trampoline_data.insert(trampoline_data.end(), detourx.begin(), detourx.end());

    if (!this->write(trampoline, trampoline_data)) {
        clean_trampoline = true;
        return nullptr;
    }

    auto detouro = WriteJumper(reinterpret_cast<void*>(original), reinterpret_cast<void*>(hook), false);
    if (!this->write(original, detouro)) {
        clean_trampoline = true;
        return nullptr;
    }

    return make_unique<WinHookHandle>(reinterpret_cast<void*>(original), trampoline, detour_data);
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