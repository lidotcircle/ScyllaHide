#pragma once
#include <windows.h>
#include "..\HookLibrary\HookMain.h"

#include "process/win_process_native.h"
#include <memory>
using Process_t = std::shared_ptr<WinProcessNative>;

extern uint16_t udpPort;
extern uint32_t udpAddr;

void ApplyPEBPatch(HANDLE hProcess, DWORD flags);
void ApplyNtdllVersionPatch(HANDLE hProcess);
bool ApplyHook(HOOK_DLL_DATA * hdd, Process_t process, BYTE * dllMemory, DWORD_PTR imageBase);
void RestoreHooks(HOOK_DLL_DATA * hdd, Process_t process);
