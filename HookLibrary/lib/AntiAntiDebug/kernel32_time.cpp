#include <Windows.h>
#include <ntdll/ntdll.h>
#include "hook_main.h"
#include "hook_helper.h"
#include "exchange_data.h"


static DWORD OneTickCount = 0;

DLLExport_C DWORD WINAPI HookedGetTickCount(void)
{
    if (!OneTickCount)
    {
        auto dGetTickCount =
            exchange_data.lookup_trampoline<decltype(&GetTickCount)>(&GetTickCount);

        OneTickCount = dGetTickCount();
    }
    else
    {
        OneTickCount++;
    }
    return OneTickCount;
}

DLLExport_C ULONGLONG WINAPI HookedGetTickCount64(void) //yes we can use DWORD
{
    if (!OneTickCount)
    {
        auto dGetTickCount =
            exchange_data.lookup_trampoline<decltype(&GetTickCount)>( &GetTickCount);

        if (dGetTickCount) {
            OneTickCount = dGetTickCount();
        } else {
            OneTickCount = RtlGetTickCount();
        }
    }
    else
    {
        OneTickCount++;
    }
    return OneTickCount;
}

static SYSTEMTIME OneLocalTime = {0};
static SYSTEMTIME OneSystemTime = {0};

DLLExport_C void WINAPI HookedGetLocalTime(LPSYSTEMTIME lpSystemTime)
{
    auto dGetSystemTime = exchange_data.lookup_trampoline<decltype(&GetSystemTime)>(&GetSystemTime);

    if (!OneLocalTime.wYear)
    {
        RealGetLocalTime(&OneLocalTime);

        if (dGetSystemTime)
        {
            RealGetSystemTime(&OneSystemTime);
        }
    }
    else
    {
        IncreaseSystemTime(&OneLocalTime);

        if (dGetSystemTime)
        {
            IncreaseSystemTime(&OneSystemTime);
        }
    }

    if (lpSystemTime)
    {
        memcpy(lpSystemTime, &OneLocalTime, sizeof(SYSTEMTIME));
    }
}

DLLExport_C void WINAPI HookedGetSystemTime(LPSYSTEMTIME lpSystemTime)
{
    auto dGetLocalTime = exchange_data.lookup_trampoline<decltype(&GetLocalTime)>(&GetLocalTime);

    if (!OneSystemTime.wYear)
    {
        RealGetSystemTime(&OneSystemTime);

        if (dGetLocalTime)
        {
            RealGetLocalTime(&OneLocalTime);
        }
    }
    else
    {
        IncreaseSystemTime(&OneSystemTime);

        if (dGetLocalTime)
        {
            IncreaseSystemTime(&OneLocalTime);
        }
    }

    if (lpSystemTime)
    {
        memcpy(lpSystemTime, &OneSystemTime, sizeof(SYSTEMTIME));
    }
}