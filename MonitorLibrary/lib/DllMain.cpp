#include <ntdll/ntdll.h>
#include <Windows.h>

#ifdef NOT_USING_MSVC_ENTRY
#pragma comment(linker, "/ENTRY:DllMain")
#endif

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    LdrDisableThreadCalloutsForDll(hinstDLL);
    return TRUE;
}
