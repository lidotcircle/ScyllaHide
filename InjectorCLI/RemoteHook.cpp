#include "RemoteHook.h"
#include "process/win_process_native.h"
#include "process/memory_map_module.h"
#include "process/memory_map_win_page.h"
#include <memory>
#include <stdexcept>
#include <distorm/distorm.h>
#include <distorm/mnemonics.h>
#include <Scylla/OsInfo.h>
#include <Scylla/Settings.h>
#include <Scylla/Peb.h>
#include "ApplyHooking.h"
#include <stdio.h>
#include <iostream>
using namespace std;


// GDT selector numbers on AMD64
#define KGDT64_R3_CMCODE (2 * 16)   // user mode 32-bit code
#define KGDT64_R3_CODE (3 * 16)     // user mode 64-bit code
#define RPL_MASK 3

#if !defined(_WIN64)
_DecodeType DecodingType = Decode32Bits;
#else
_DecodeType DecodingType = Decode64Bits;
#endif

#ifdef _WIN64
const int minDetourLen = 2 + sizeof(DWORD)+sizeof(DWORD_PTR) + 1; //8+4+2+1=15
#else
const int minDetourLen = sizeof(DWORD) + 1;
const int detourLenWow64FarJmp = 1 + sizeof(DWORD) + sizeof(USHORT); // EA far jmp
#endif


extern scl::Settings g_settings;
extern void * HookedNativeCallInternal;
extern void * NativeCallContinue;
extern HOOK_NATIVE_CALL32 * HookNative;
extern int countNativeHooks;
extern bool onceNativeCallContinue;
extern bool fatalFindSyscallIndexFailure;
extern bool fatalAlreadyHookedFailure;

BYTE originalBytes[60] = { 0 };
BYTE changedBytes[60] = { 0 };

void WriteJumper(unsigned char * lpbFrom, unsigned char * lpbTo)
{
#ifdef _WIN64
    lpbFrom[0] = 0xFF;
    lpbFrom[1] = 0x25;
    *(DWORD*)&lpbFrom[2] = 0;
    *(DWORD_PTR*)&lpbFrom[6] = (DWORD_PTR)lpbTo;
#else
    lpbFrom[0] = 0xE9;
    *(DWORD*)&lpbFrom[1] = (DWORD)((DWORD)lpbTo - (DWORD)lpbFrom - 5);
#endif
}

void WriteJumper(unsigned char * lpbFrom, unsigned char * lpbTo, unsigned char * buf, bool prefixNop)
{
#ifdef _WIN64
    UNREFERENCED_PARAMETER(lpbFrom);

    ULONG i = 0;
    if (prefixNop)
        buf[i++] = 0x90;

    buf[i] = 0xFF;
    buf[i + 1] = 0x25;
    *(DWORD*)&buf[i + 2] = 0;
    *(DWORD_PTR*)&buf[i + 6] = (DWORD_PTR)lpbTo;
#else
    UNREFERENCED_PARAMETER(prefixNop);

    buf[0] = 0xE9;
    *(DWORD*)&buf[1] = (DWORD)((DWORD)lpbTo - (DWORD)lpbFrom - 5);
#endif
}

#ifndef _WIN64
void WriteWow64Jumper(unsigned char * lpbTo, unsigned char * buf)
{
    // Preserve EA prefix (absolute far jmp), but use the 32 bit segment selector to avoid transitioning into x64 mode
    buf[0] = 0xEA;
    *(DWORD*)&buf[1] = (DWORD)lpbTo;
    *(USHORT*)&buf[5] = (USHORT)(KGDT64_R3_CMCODE | RPL_MASK);
}
#endif

void ClearSyscallBreakpoint(const char* funcName, unsigned char* funcBytes)
{
    // Do nothing if this is not a syscall stub
    if ((funcName == nullptr || funcName[0] == '\0') ||
        (funcName[0] != 'N' || funcName[1] != 't') &&
        (funcName[0] != 'Z' || funcName[1] != 'w'))
        return;

    if (funcBytes[0] == 0xCC || // int 3
        (funcBytes[0] == 0xCD && funcBytes[1] == 0x03) || // long int 3
        (funcBytes[0] == 0xF0 && funcBytes[1] == 0x0B)) // UD2
    {
#ifdef _WIN64
        // x64 stubs always start with 'mov r10, rcx'
        funcBytes[0] = 0x4C;
        funcBytes[1] = 0x8B;
#else
        // For x86 and WOW64 stubs, we can only restore int 3 breakpoints since the second byte is the (unknown) syscall number
        if (funcBytes[0] != 0xCC)
            MessageBoxA(nullptr, "ClearSyscallBreakpoint failed! Please use INT 3 breakpoints instead of long INT 3 or UD2.", "ScyllaHide", MB_ICONERROR);
        else
            funcBytes[0] = 0xB8; // mov eax, <syscall num>
#endif
    }
}

#ifndef _WIN64

DWORD GetEcxSysCallIndex32(const BYTE * data, int dataSize)
{
    unsigned int DecodedInstructionsCount = 0;
    _CodeInfo decomposerCi = { 0 };
    _DInst decomposerResult[10] = { 0 };

    decomposerCi.code = data;
    decomposerCi.codeLen = dataSize;
    decomposerCi.dt = DecodingType;
    decomposerCi.codeOffset = (LONG_PTR)data;

    if (distorm_decompose(&decomposerCi, decomposerResult, _countof(decomposerResult), &DecodedInstructionsCount) != DECRES_INPUTERR)
    {
        if (decomposerResult[0].flags != FLAG_NOT_DECODABLE && decomposerResult[1].flags != FLAG_NOT_DECODABLE)
        {
            if (decomposerResult[0].opcode == I_MOV && decomposerResult[1].opcode == I_MOV)
            {
                if (decomposerResult[1].ops[0].index == R_ECX)
                {
                    return decomposerResult[1].imm.dword;
                }
            }
        }
    }

    return 0;
}

DWORD GetSysCallIndex32(const BYTE * data)
{
    unsigned int DecodedInstructionsCount = 0;
    _CodeInfo decomposerCi = { 0 };
    _DInst decomposerResult[1] = { 0 };

    decomposerCi.code = data;
    decomposerCi.codeLen = MAXIMUM_INSTRUCTION_SIZE;
    decomposerCi.dt = DecodingType;
    decomposerCi.codeOffset = (LONG_PTR)data;

    if (distorm_decompose(&decomposerCi, decomposerResult, _countof(decomposerResult), &DecodedInstructionsCount) != DECRES_INPUTERR)
    {
        if (decomposerResult[0].flags != FLAG_NOT_DECODABLE)
        {
            if (decomposerResult[0].opcode == I_MOV)
            {
                return decomposerResult[0].imm.dword;
            }
            else
            {
                MessageBoxA(nullptr, "GetSysCallIndex32: Opcode is not I_MOV", "Distorm ERROR", MB_ICONERROR);
            }
        }
        else
        {
            MessageBoxA(nullptr, "GetSysCallIndex32: Distorm flags == FLAG_NOT_DECODABLE", "Distorm ERROR", MB_ICONERROR);
        }
    }
    else
    {
        MessageBoxA(nullptr, "GetSysCallIndex32: distorm_decompose() returned DECRES_INPUTERR", "Distorm ERROR", MB_ICONERROR);
    }

    return (DWORD)-1; // Don't return 0 here, it is a valid syscall index
}

DWORD GetCallDestination(Process_t process, const BYTE * data, int dataSize)
{
    unsigned int DecodedInstructionsCount = 0;
    _CodeInfo decomposerCi = { 0 };
    _DInst decomposerResult[100] = { 0 };

    decomposerCi.code = data;
    decomposerCi.codeLen = dataSize;
    decomposerCi.dt = DecodingType;
    decomposerCi.codeOffset = (LONG_PTR)data;

    if (distorm_decompose(&decomposerCi, decomposerResult, _countof(decomposerResult), &DecodedInstructionsCount) != DECRES_INPUTERR)
    {
        if (DecodedInstructionsCount > 2)
        {
            //B8 EA000000      MOV EAX,0EA
            //BA 0003FE7F      MOV EDX,7FFE0300
            //FF12             CALL DWORD PTR DS:[EDX]
            //C2 1400          RETN 14
            //0xB8,0xEA,0x00,0x00,0x00,0xBA,0x00,0x03,0xFE,0x7F,0xFF,0x12,0xC2,0x14,0x00

            //MOV EAX,0EA
            //MOV EDX, 7FFE0300h ; EDX = 7FFE0300h
            //	CALL EDX ; call 7FFE0300h
            //	RETN 14
            //0xB8,0xEA,0x00,0x00,0x00,0xBA,0x00,0x03,0xFE,0x7F,0xFF,0xD2,0xC2,0x14,0x00

            if (decomposerResult[0].flags != FLAG_NOT_DECODABLE && decomposerResult[1].flags != FLAG_NOT_DECODABLE)
            {
                if (decomposerResult[0].opcode == I_MOV && decomposerResult[1].opcode == I_MOV && decomposerResult[2].opcode == I_CALL)
                {
                    if (decomposerResult[2].ops[0].type == O_SMEM) //CALL DWORD PTR DS:[EDX]
                    {
                        DWORD pKUSER_SHARED_DATASysCall = decomposerResult[1].imm.dword;
                        if (pKUSER_SHARED_DATASysCall)
                        {
                            DWORD callDestination = 0;
                            process->read((void*)pKUSER_SHARED_DATASysCall, &callDestination, sizeof(DWORD));
                            return callDestination;
                        }
                    }
                    else if (decomposerResult[2].ops[0].type == O_REG) //CALL EDX
                    {
                        return decomposerResult[1].imm.dword;
                    }
                }
            }

            MessageBoxA(nullptr, "Unknown syscall structure!", "ScyllaHide", 0);
        }
    }

    return NULL;
}

DWORD GetFunctionSizeRETN(BYTE * data, int dataSize)
{
    unsigned int DecodedInstructionsCount = 0;
    _CodeInfo decomposerCi = { 0 };
    _DInst decomposerResult[100] = { 0 };

    decomposerCi.code = data;
    decomposerCi.codeLen = dataSize;
    decomposerCi.dt = DecodingType;
    decomposerCi.codeOffset = (LONG_PTR)data;

    if (distorm_decompose(&decomposerCi, decomposerResult, _countof(decomposerResult), &DecodedInstructionsCount) != DECRES_INPUTERR)
    {
        for (unsigned int i = 0; i < DecodedInstructionsCount; i++)
        {
            if (decomposerResult[i].flags != FLAG_NOT_DECODABLE)
            {
                if (decomposerResult[i].opcode == I_RET)
                {
                    return (DWORD)(((DWORD_PTR)decomposerResult[i].addr + (DWORD_PTR)decomposerResult[i].size) - (DWORD_PTR)data);
                }
            }
        }

    }

    return 0;
}

DWORD GetCallOffset(const BYTE * data, int dataSize, DWORD * callSize)
{
    unsigned int DecodedInstructionsCount = 0;
    _CodeInfo decomposerCi = { 0 };
    _DInst decomposerResult[100] = { 0 };

    decomposerCi.code = data;
    decomposerCi.codeLen = dataSize;
    decomposerCi.dt = DecodingType;
    decomposerCi.codeOffset = (LONG_PTR)data;

    if (distorm_decompose(&decomposerCi, decomposerResult, _countof(decomposerResult), &DecodedInstructionsCount) != DECRES_INPUTERR)
    {
        for (unsigned int i = 0; i < DecodedInstructionsCount; i++)
        {
            if (decomposerResult[i].flags != FLAG_NOT_DECODABLE)
            {
                if (decomposerResult[i].opcode == I_CALL || decomposerResult[i].opcode == I_CALL_FAR)
                {
                    *callSize = decomposerResult[i].size;
                    return (DWORD)((DWORD_PTR)decomposerResult[i].addr - (DWORD_PTR)data);
                }
            }
        }

    }

    return 0;
}

ULONG_PTR FindPattern(ULONG_PTR base, ULONG size, const UCHAR* pattern, ULONG patternSize)
{
    for (PUCHAR Address = (PUCHAR)base; Address < (PUCHAR)(base + size - patternSize); ++Address)
    {
        ULONG i;
        for (i = 0; i < patternSize; ++i)
        {
            if (pattern[i] != 0xCC && (*(Address + i) != pattern[i]))
                break;
        }

        if (i == patternSize)
            return (ULONG_PTR)Address;
    }
    return 0;
}

BYTE KiFastSystemCallWow64Backup[7] = { 0 };
DWORD KiFastSystemCallWow64Address = 0; // In wow64cpu.dll, named X86SwitchTo64BitMode prior to Windows 8

void * DetourCreateRemoteWow64(Process_t process, bool createTramp)
{
    cout << "DetourCreateRemoteWow64" << endl;
    PBYTE trampoline = nullptr;
    DWORD protect;
    bool onceNativeCallContinueWasSet = onceNativeCallContinue;
    onceNativeCallContinue = true;

    // NtQueryInformationProcess on Windows 10 under sysWow64 has an irregular structure, this is a call at +4 or bytes from itself
    // Another case for Windows 10 is 'call $+5'
    bool bSpecialSyscallStructure = (originalBytes[5] == 0xE8 && (originalBytes[6] == 0x04 || originalBytes[6] == 0x00));

    // We're "borrowing" another api's code as a template, the ret must match
    if (bSpecialSyscallStructure)
    {
        //g_log.LogDebug(L"NtQueryInformationProcess Windows 10 detected");

        BYTE syscallAddressBytes[5];	// save syscall id eg. Mov eax, 0x19

        memcpy(syscallAddressBytes, originalBytes, sizeof(syscallAddressBytes));			// Copy the syscall id bytes

        //g_log.LogDebug(L"syscallAddressBytes: %x", syscallAddressBytes);

        // This is a "normal" function and both have a ret 14
        DWORD ntQueryKey = (DWORD)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryKey");

        //g_log.LogDebug(L"NtQueryKey address: %x", ntQueryKey);

        process->read((PVOID)ntQueryKey, &originalBytes, sizeof(originalBytes));
        process->read((PVOID)ntQueryKey, &changedBytes, sizeof(originalBytes));

        memcpy(originalBytes, syscallAddressBytes, sizeof(syscallAddressBytes));
        memcpy(changedBytes, syscallAddressBytes, sizeof(syscallAddressBytes));
    }

    DWORD funcSize = GetFunctionSizeRETN(originalBytes, sizeof(originalBytes));
    DWORD callSize = 0;
    DWORD callOffset = GetCallOffset(originalBytes, sizeof(originalBytes), &callSize);

    if (!onceNativeCallContinueWasSet)
    {
        if (NtCurrentPeb()->OSBuildNumber >= 14393) // Windows 10 >= RS1?
        {
            // ntdll32!Wow64Transition will point to wow64cpu!KiFastSystemCall in 99% of cases. However, it is possible that the process
            // has the 'prohibit dynamic code execution' mitigation enabled, in which case it will point to the no fun allowed version
            // wow64cpu!KiFastSystemCall2, which pushes the x64 segment selector on the stack to do a jmp far fword ptr [esp] (FF 2C 24).
            // Hooking KiFastSystemCall2 is pointless because ScyllaHide is mega incompatible with the entire mitigation policy anyway due to its many RWX allocations.
            PVOID* pWow64Transition = (PVOID*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "Wow64Transition");
            ULONG Wow64Transition = 0;
            if (pWow64Transition != nullptr &&
                process->read(pWow64Transition, &Wow64Transition, sizeof(Wow64Transition)) &&
                Wow64Transition != 0)
            {
                if (((PUCHAR)Wow64Transition)[0] != 0xEA)
                {
                    MessageBoxA(nullptr, "Wow64Transition[0] != 0xEA! The process is probably prohibiting dynamic code execution.", "ScyllaHide", MB_ICONERROR);
                    return nullptr;
                }

                KiFastSystemCallWow64Address = Wow64Transition;
            }
        }

        if (KiFastSystemCallWow64Address == 0)
        {
            ULONG64 Wow64cpu = (ULONG64)scl::Wow64GetModuleHandle64(process->rawhandle(), L"wow64cpu.dll");
            if (Wow64cpu == 0 || Wow64cpu > (ULONG32)Wow64cpu) // wow64cpu.dll should always be below 4GB
            {
                MessageBoxA(nullptr, "Failed to obtain address of wow64cpu.dll!", "ScyllaHide", MB_ICONERROR);
                return nullptr;
            }

            // EA XXXXXXXX 3300
            // ^ absolute non-indirect far jmp
            //    ^ 32 bit address
            //             ^ x64 cs segment selector
            constexpr UCHAR Wow64FarJmpPattern[] = { 0xEA, 0xCC, 0xCC, 0xCC, 0xCC, (UCHAR)(KGDT64_R3_CODE | RPL_MASK), 0x00 };

            PIMAGE_NT_HEADERS64 NtHeaders64 = (PIMAGE_NT_HEADERS64)RtlImageNtHeader((PVOID)Wow64cpu);
            PIMAGE_SECTION_HEADER TextSection = IMAGE_FIRST_SECTION(NtHeaders64);
            KiFastSystemCallWow64Address = (ULONG)FindPattern((ULONG_PTR)Wow64cpu + TextSection->VirtualAddress,
                NtHeaders64->OptionalHeader.SizeOfImage - TextSection->Misc.VirtualSize, Wow64FarJmpPattern, sizeof(Wow64FarJmpPattern));
            if (KiFastSystemCallWow64Address == 0)
            {
                // For when you're debugging the debugger and forget to turn off your own hooks...
                constexpr UCHAR Wow64FarJmpIntoX86Pattern[] = { 0xEA, 0xCC, 0xCC, 0xCC, 0xCC, (UCHAR)(KGDT64_R3_CMCODE | RPL_MASK), 0x00 };
                KiFastSystemCallWow64Address = (ULONG)FindPattern((ULONG_PTR)Wow64cpu + TextSection->VirtualAddress,
                    NtHeaders64->OptionalHeader.SizeOfImage - TextSection->Misc.VirtualSize, Wow64FarJmpIntoX86Pattern, sizeof(Wow64FarJmpIntoX86Pattern));
            }
                
            if (KiFastSystemCallWow64Address == 0)
            {
                MessageBoxA(nullptr, "Failed to find KiFastSystemCall/X86SwitchTo64BitMode in wow64cpu.dll!", "ScyllaHide", MB_ICONERROR);
                return nullptr;
            }
        }

        if (process->read((void*)KiFastSystemCallWow64Address, KiFastSystemCallWow64Backup, sizeof(KiFastSystemCallWow64Backup)))
        {
            if (KiFastSystemCallWow64Backup[5] == (KGDT64_R3_CMCODE | RPL_MASK))
            {
                // PENDING: it should be safe to just undo this since we are likely the only ones using this retarded 'far jmp into x86' type hook
                //fatalAlreadyHookedFailure = true;
                MessageBoxA(nullptr, "KiFastSystemCall/X86SwitchTo64BitMode in wow64cpu.dll is already hooked! Trying to salvage this...", "ScyllaHide", MB_ICONWARNING);
                //return nullptr;

                KiFastSystemCallWow64Backup[5] = (KGDT64_R3_CODE | RPL_MASK);
            }

            NativeCallContinue = process->malloc(sizeof(KiFastSystemCallWow64Backup), 1, PAGE_EXECUTE_READWRITE);
            cout << "NativeCallContinue: " << NativeCallContinue << endl;
            if (!process->write(NativeCallContinue, KiFastSystemCallWow64Backup, sizeof(KiFastSystemCallWow64Backup)))
            {
                MessageBoxA(nullptr, "Failed to write NativeCallContinue routine", "ScyllaHide", MB_ICONERROR);
                return nullptr;
            }
        }
        else
        {
            MessageBoxA(nullptr, "Failed to read KiFastSystemCall/X86SwitchTo64BitMode bytes in wow64cpu.dll", "ScyllaHide", MB_ICONERROR);
            return nullptr;
        }
    }

    if (funcSize != 0 && createTramp)
    {
        trampoline = (PBYTE)process->malloc(sizeof(changedBytes), 1, PAGE_EXECUTE_READWRITE);
        if (trampoline == nullptr)
            return nullptr;

        changedBytes[callOffset] = 0x68; //PUSH
        *((DWORD*)&changedBytes[callOffset + 1]) = ((DWORD)trampoline + (DWORD)callOffset + 5 + 7);
        memcpy(changedBytes + callOffset + 5, KiFastSystemCallWow64Backup, sizeof(KiFastSystemCallWow64Backup));

        memcpy(changedBytes + callOffset + 5 + sizeof(KiFastSystemCallWow64Backup), originalBytes + callOffset + callSize, funcSize - callOffset - callSize);

        cout << "trampoline: " << (void*)trampoline << endl;
        process->write(trampoline, changedBytes, sizeof(changedBytes));
    }

    if (!onceNativeCallContinueWasSet)
    {
        // Write a faux WOW64 transition far jmp with disregard for space used
        UCHAR jumperBytes[detourLenWow64FarJmp];
        RtlZeroMemory(jumperBytes, sizeof(jumperBytes));
        WriteWow64Jumper((PBYTE)HookedNativeCallInternal, jumperBytes);
        cout << "KiFastSystemCallWow64Address: " << (void*)KiFastSystemCallWow64Address << endl;
        if (!process->write((void *)KiFastSystemCallWow64Address, jumperBytes, detourLenWow64FarJmp))
        {
            MessageBoxA(nullptr, "Failed to write KiFastSystemCall/X86SwitchTo64BitMode replacement to wow64cpu.dll", "ScyllaHide", MB_ICONERROR);
        }
   }

    return trampoline;
}

//7C91E4F0 ntdll.KiFastSystemCall  EB F9   JMP 7C91E4EB

BYTE KiFastSystemCallJmpPatch[] = { 0xE9, 0x00, 0x00, 0x00, 0x00, 0xEB, 0xF9 };
BYTE KiFastSystemCallBackup[20] = { 0 };
DWORD KiFastSystemCallAddress = 0;
DWORD KiFastSystemCallBackupSize = 0;

void * DetourCreateRemoteX86(Process_t process, bool createTramp)
{
    cout << "DetourCreateRemoteX86" << endl;
    PBYTE trampoline = 0;
    DWORD protect;

    DWORD funcSize = GetFunctionSizeRETN(originalBytes, sizeof(originalBytes));

    DWORD callSize = 0;
    DWORD callOffset = GetCallOffset(originalBytes, sizeof(originalBytes), &callSize);
    KiFastSystemCallAddress = GetCallDestination(process, originalBytes, sizeof(originalBytes));

    if (!onceNativeCallContinue)
    {
        process->read((void*)KiFastSystemCallAddress, KiFastSystemCallBackup, sizeof(KiFastSystemCallBackup));
        KiFastSystemCallBackupSize = GetFunctionSizeRETN(KiFastSystemCallBackup, sizeof(KiFastSystemCallBackup));
        if (KiFastSystemCallBackupSize)
        {
            NativeCallContinue = process->malloc(KiFastSystemCallBackupSize, 1, PAGE_EXECUTE_READWRITE);
            if (NativeCallContinue)
            {
                process->write(NativeCallContinue, KiFastSystemCallBackup, KiFastSystemCallBackupSize);
            }
            else
            {
                MessageBoxA(nullptr, "DetourCreateRemoteX86 -> NativeCallContinue", "ScyllaHide", MB_ICONERROR);
            }
        }
        else
        {
            MessageBoxA(nullptr, "DetourCreateRemoteX86 -> KiSystemCallBackupSize", "ScyllaHide", MB_ICONERROR);
        }
    }

    if (funcSize && createTramp)
    {
        trampoline = (PBYTE)process->malloc(sizeof(changedBytes), 1, PAGE_EXECUTE_READWRITE);
        if (!trampoline)
            return nullptr;

        changedBytes[callOffset] = 0x68; //PUSH
        *((DWORD*)&changedBytes[callOffset + 1]) = ((DWORD)trampoline + (DWORD)callOffset + 5 + KiFastSystemCallBackupSize);
        memcpy(changedBytes + callOffset + 5, KiFastSystemCallBackup, KiFastSystemCallBackupSize);

        memcpy(changedBytes + callOffset + 5 + KiFastSystemCallBackupSize, originalBytes + callOffset + callSize, funcSize - callOffset - callSize);

        process->write(trampoline, changedBytes, sizeof(changedBytes));
    }

    if (!onceNativeCallContinue)
    {
        DWORD_PTR patchAddr = (DWORD_PTR)KiFastSystemCallAddress - 5;

        WriteJumper((PBYTE)patchAddr, (PBYTE)HookedNativeCallInternal, KiFastSystemCallJmpPatch, false);
        process->write((void *)patchAddr, KiFastSystemCallJmpPatch, 5 + 2);

        onceNativeCallContinue = true;
    }

    return trampoline;
}

void * DetourCreateRemote32(Process_t process, const char* funcName, void * lpFuncOrig, void * lpFuncDetour, bool createTramp, unsigned long * backupSize)
{
    cout << "DetourCreateRemote32(" << funcName << ", " << lpFuncOrig << ", " << lpFuncDetour << ")" << endl;
    if (!scl::IsWow64Process(process->rawhandle()))
    {
        // Handle special cases on native x86 where hooks should be placed inside the function and not at KiFastSystemCall.
        // TODO: why does DetourCreateRemoteX86 even exist? DetourCreateRemote works fine on any OS
        if (scl::GetWindowsVersion() >= scl::OS_WIN_8)
        {
            // The native x86 syscall structure was changed in Windows 8. https://github.com/x64dbg/ScyllaHide/issues/49
            return DetourCreateRemote(process, funcName, lpFuncOrig, lpFuncDetour, createTramp, backupSize);
        }

        if (g_settings.profile_name().find(L"Obsidium") != std::wstring::npos)
        {
            // This is an extremely lame hack because Obsidium doesn't like where we put our hooks
            return DetourCreateRemote(process, funcName, lpFuncOrig, lpFuncDetour, createTramp, backupSize);
        }
    }

    if (fatalFindSyscallIndexFailure || fatalAlreadyHookedFailure)
        return nullptr; // Don't spam user with repeated error message boxes

    memset(changedBytes, 0x90, sizeof(changedBytes));
    memset(originalBytes, 0x90, sizeof(originalBytes));

    if (!process->read(lpFuncOrig, originalBytes, sizeof(originalBytes)))
    {
        MessageBoxA(nullptr, "DetourCreateRemoteX86->ReadProcessMemory failed.", "ScyllaHide", MB_ICONERROR);
        return nullptr;
    }

    ClearSyscallBreakpoint(funcName, originalBytes);

    memcpy(changedBytes, originalBytes, sizeof(originalBytes));

    DWORD sysCallIndex = GetSysCallIndex32(originalBytes);

    if (sysCallIndex == (DWORD)-1)
    {
        fatalFindSyscallIndexFailure = true; // Do not attempt any more hooks after this
        char errorMessage[256];
        _snprintf_s(errorMessage, sizeof(errorMessage), sizeof(errorMessage) - sizeof(char),
            "Error: syscall index of %hs not found.\nThis can happen if the function is already hooked, or if it contains a breakpoint.", funcName);
        MessageBoxA(nullptr, errorMessage, "ScyllaHide", MB_ICONERROR);
        return nullptr;
    }

    HookNative[countNativeHooks].eaxValue = sysCallIndex;
    HookNative[countNativeHooks].ecxValue = 0;
    HookNative[countNativeHooks].hookedFunction = lpFuncDetour;

    PVOID result;
    if (!scl::IsWow64Process(process->rawhandle()))
    {
        result = DetourCreateRemoteX86(process, createTramp);
    }
    else
    {
        HookNative[countNativeHooks].ecxValue = GetEcxSysCallIndex32(originalBytes, sizeof(originalBytes));
        result = DetourCreateRemoteWow64(process, createTramp);
    }

    countNativeHooks++;

    return result;
}

#endif

void * DetourCreateRemote(Process_t process, const char* funcName, void * lpFuncOrig, void * lpFuncDetour, bool createTramp, DWORD * backupSize)
{
    cout << "DetourCreateRemote(" << funcName << ", " << lpFuncOrig << ", " << lpFuncDetour << ")" << endl;
    BYTE originalBytes[50] = { 0 };
    BYTE tempSpace[1000] = { 0 };
    PBYTE trampoline = 0;
    DWORD protect;

    bool success = false;

    if (fatalFindSyscallIndexFailure || fatalAlreadyHookedFailure)
        return nullptr; // Don't spam user with repeated error message boxes

    if (!process->read(lpFuncOrig, originalBytes, sizeof(originalBytes)))
        return nullptr;

    ClearSyscallBreakpoint(funcName, originalBytes);

    // Note that this check will give a false negative in the case that a function is hooked *and* has a breakpoint set on it (now cleared).
    // We can clear the breakpoint or detect the hook, not both. (If the hook is ours, this is actually a hack because we should be properly unhooking)
#ifdef _WIN64
    const bool isHooked = (originalBytes[0] == 0xFF && originalBytes[1] == 0x25) ||
        (originalBytes[0] == 0x90 && originalBytes[1] == 0xFF && originalBytes[2] == 0x25);
#else
    const bool isHooked = originalBytes[0] == 0xE9;
#endif
    if (isHooked)
    {
        throw runtime_error("Error: function '" + string(funcName) + "' is already hooked.");
        return nullptr;
    }

    int detourLen = GetDetourLen(originalBytes, minDetourLen);

    if (createTramp)
    {
        *backupSize = detourLen;

        trampoline = (PBYTE)process->malloc(detourLen + minDetourLen, 1, PAGE_EXECUTE_READWRITE);
        if (!trampoline)
            return 0;

        if (!process->write(trampoline, originalBytes, detourLen)) 
            return 0;

        ZeroMemory(tempSpace, sizeof(tempSpace));
        WriteJumper(trampoline + detourLen, (PBYTE)lpFuncOrig + detourLen, tempSpace, false);
        process->write(trampoline + detourLen, tempSpace, minDetourLen);
    }

    ZeroMemory(tempSpace, sizeof(tempSpace));
    WriteJumper((PBYTE)lpFuncOrig, (PBYTE)lpFuncDetour, tempSpace, scl::IsWindows64() && !scl::IsWow64Process(NtCurrentProcess));
    process->write(lpFuncOrig, tempSpace, minDetourLen);
    success = true;

    if (createTramp)
    {
        if (!success)
        {
            trampoline = nullptr;
        }
        return trampoline;
    }
    else
    {
        return 0;
    }
}

void * DetourCreate(void * lpFuncOrig, void * lpFuncDetour, bool createTramp)
{
    PBYTE trampoline = 0;
    DWORD protect;

    bool success = false;

    int detourLen = GetDetourLen(lpFuncOrig, minDetourLen);

    if (createTramp)
    {
        trampoline = (PBYTE)VirtualAlloc(0, detourLen + minDetourLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!trampoline)
            return 0;

        memcpy(trampoline, lpFuncOrig, detourLen);
        WriteJumper(trampoline + detourLen, (PBYTE)lpFuncOrig + detourLen);
        VirtualProtect(trampoline, detourLen + minDetourLen, PAGE_EXECUTE_READ, &protect);
    }


    if (VirtualProtect(lpFuncOrig, detourLen, PAGE_EXECUTE_READWRITE, &protect))
    {
        WriteJumper((PBYTE)lpFuncOrig, (PBYTE)lpFuncDetour);

        VirtualProtect(lpFuncOrig, detourLen, protect, &protect);
        success = true;
    }

    if (createTramp)
    {
        if (!success)
        {
            VirtualFree(trampoline, 0, MEM_RELEASE);
            trampoline = 0;
        }
        return trampoline;
    }
    else
    {
        return 0;
    }
}

int GetDetourLen(const void * lpStart, const int minSize)
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

int LengthDisassemble(LPVOID DisassmAddress)
{
    unsigned int DecodedInstructionsCount = 0;
    _CodeInfo decomposerCi = { 0 };
    _DInst decomposerResult[1] = { 0 };

    decomposerCi.code = (BYTE *)DisassmAddress;
    decomposerCi.codeLen = MAXIMUM_INSTRUCTION_SIZE;
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
