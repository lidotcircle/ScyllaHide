#include <ntdll/ntdll.h>
#include <string>

#ifdef NOT_USING_MSVC_ENTRY
#pragma comment(linker, "/ENTRY:DllMain")
#endif

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    std::string s("hello");
    LdrDisableThreadCalloutsForDll(hinstDLL);
    return TRUE;
}