#pragma once

#include "process/win_process_native.h"
#include "..\HookLibrary\HookMain.h"
#include <memory>
#include <windows.h>
using Process_t = std::shared_ptr<WinProcessNative>;
class MapPEModule;

extern uint16_t udpPort;
extern uint32_t udpAddr;

void ApplyPEBPatch(HANDLE hProcess, DWORD flags);
void ApplyNtdllVersionPatch(HANDLE hProcess);
bool ApplyHook(HOOK_DLL_DATA * hdd, Process_t process, std::shared_ptr<MapPEModule> module);
void RestoreHooks(HOOK_DLL_DATA * hdd, Process_t process);
