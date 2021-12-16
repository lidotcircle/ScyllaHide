#pragma once

#include "process/win_process_native.h"
#include <memory>
using Process_t = std::shared_ptr<WinProcessNative>;

#define MAXIMUM_INSTRUCTION_SIZE (16) //maximum instruction size == 16

int GetDetourLen(const void * lpStart, const int minSize);
void WriteJumper(unsigned char * lpbFrom, unsigned char * lpbTo);
void * DetourCreate(void * lpFuncOrig, void * lpFuncDetour, bool createTramp);
void * DetourCreateRemote(Process_t process, const char* funcName, void * lpFuncOrig, void * lpFuncDetour, bool createTramp, unsigned long * backupSize);

#ifdef _WIN64
#define DetourCreateRemoteNative DetourCreateRemote
#else
void * DetourCreateRemote32(Process_t process, const char* funcName, void * lpFuncOrig, void * lpFuncDetour, bool createTramp, unsigned long * backupSize);
void * DetourCreateRemoteWow64(Process_t process, bool createTramp);

#define DetourCreateRemoteNative DetourCreateRemote32
#endif

int LengthDisassemble(void* DisassmAddress);
