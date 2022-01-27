#include <Windows.h>
#include "exchange_data.h"
#include "hook_main.h"
#include "hook_helper.h"
#include "hook_log_client.h"


// GetLastError() function might not change if a  debugger is present (it has never been the case that it is always set to zero).
DLLExport_C DWORD WINAPI HookedOutputDebugStringA(LPCSTR lpOutputString) //Worst anti-debug ever
{
    if (RtlNtMajorVersion() >= 6) // Vista or later
        return 0;

    NtCurrentTeb()->LastErrorValue = NtCurrentTeb()->LastErrorValue + 1; //change last error
    return 1; //WinXP EAX -> 1
}