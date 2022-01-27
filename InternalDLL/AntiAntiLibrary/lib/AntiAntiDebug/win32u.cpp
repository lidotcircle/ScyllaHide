#include <Windows.h>
#include "exchange_data.h"
#include "hook_main.h"
#include "hook_helper.h"
#include "hook_log_client.h"


static BOOL isBlocked = FALSE;
DLLExport_C BOOL NTAPI HookedNtUserBlockInput(BOOL fBlockIt)
{
    if (isBlocked == FALSE && fBlockIt != FALSE)
    {
        isBlocked = TRUE;
        return TRUE;
    }
    else if (isBlocked != FALSE && fBlockIt == FALSE)
    {
        isBlocked = FALSE;
        return TRUE;
    }

    return FALSE;
}


DLLExport_C HANDLE NTAPI HookedNtUserQueryWindow(HWND hwnd, WINDOWINFOCLASS WindowInfo)
{
    if ((WindowInfo == WindowProcess || WindowInfo == WindowThread) && IsWindowBad(hwnd))
    {
        if (WindowInfo == WindowProcess)
            return NtCurrentTeb()->ClientId.UniqueProcess;
        if (WindowInfo == WindowThread)
            return NtCurrentTeb()->ClientId.UniqueThread;
    }
    auto dNtUserQueryWindow =
        exchange_data.lookup_trampoline<decltype(&HookedNtUserQueryWindow)>("NtUserQueryWindow");
    return dNtUserQueryWindow(hwnd, WindowInfo);
}



DLLExport_C HWND NTAPI HookedNtUserFindWindowEx(HWND hWndParent, HWND hWndChildAfter, PUNICODE_STRING lpszClass, PUNICODE_STRING lpszWindow, DWORD dwType)
{
    auto dNtUserFindWindowEx =
        exchange_data.lookup_trampoline<decltype(&HookedNtUserFindWindowEx)>("NtUserFindWindowEx");
    HWND resultHwnd = dNtUserFindWindowEx(hWndParent, hWndChildAfter, lpszClass, lpszWindow, dwType);
    if (resultHwnd)
    {
        if (IsWindowClassNameBad(lpszClass) || IsWindowNameBad(lpszWindow))
        {
            return 0;
        }

        auto dNtUserQueryWindow =
            exchange_data.lookup_trampoline<decltype(&HookedNtUserQueryWindow)>("NtUserQueryWindow");

        auto enableProtecteProcessId =
            exchange_data.lookup_key("EnableProtecteProcessId");
        if (enableProtecteProcessId)
        {
            DWORD dwProcessId;
            if (dNtUserQueryWindow)
            {
                dwProcessId = HandleToULong(dNtUserQueryWindow(resultHwnd, WindowProcess));
            }
            else
            {
                dwProcessId = HandleToULong(HookedNtUserQueryWindow(resultHwnd, WindowProcess));
            }

            auto protecteProcessId =
                exchange_data.lookup_key("ProtecteProcessId");
            // TODO
            if (protecteProcessId)
            {
                return 0;
            }
        }
    }
    return resultHwnd;
}


static void FilterHwndList(HWND * phwndFirst, PULONG pcHwndNeeded)
{
    for (UINT i = 0; i < *pcHwndNeeded; i++)
    {
        if (phwndFirst[i] != nullptr && IsWindowBad(phwndFirst[i]))
        {
            if (i == 0)
            {
                // Find the first HWND that belongs to a different process (i + 1, i + 2... may still be ours)
                for (UINT j = i + 1; j < *pcHwndNeeded; j++)
                {
                    if (phwndFirst[j] != nullptr && !IsWindowBad(phwndFirst[j]))
                    {
                        phwndFirst[i] = phwndFirst[j];
                        break;
                    }
                }
            }
            else
            {
                phwndFirst[i] = phwndFirst[i - 1]; //just override with previous
            }
        }
    }
}

DLLExport_C NTSTATUS NTAPI HookedNtUserBuildHwndList(HDESK hDesktop, HWND hwndParent, BOOLEAN bChildren, ULONG dwThreadId, ULONG lParam, HWND* pWnd, PULONG pBufSize)
{
    auto dNtUserBuildHwndList =
        exchange_data.lookup_trampoline<decltype(&HookedNtUserBuildHwndList)>("NtUserBuildHwndList");
    NTSTATUS ntStat = dNtUserBuildHwndList(hDesktop, hwndParent, bChildren, dwThreadId, lParam, pWnd, pBufSize);

    if (NT_SUCCESS(ntStat) && pWnd != nullptr && pBufSize != nullptr)
    {
        FilterHwndList(pWnd, pBufSize);
    }

    return ntStat;
}


DLLExport_C NTSTATUS NTAPI HookedNtUserBuildHwndList_Eight(HDESK hDesktop, HWND hwndParent, BOOLEAN bChildren, BOOLEAN bUnknownFlag, ULONG dwThreadId, ULONG lParam, HWND* pWnd, PULONG pBufSize)
{
    auto dNtUserBuildHwndList =
        exchange_data.lookup_trampoline<decltype(&HookedNtUserBuildHwndList)>("NtUserBuildHwndList");
    NTSTATUS ntStat = ((t_NtUserBuildHwndList_Eight)dNtUserBuildHwndList)(hDesktop, hwndParent, bChildren, bUnknownFlag, dwThreadId, lParam, pWnd, pBufSize);

    if (NT_SUCCESS(ntStat) && pWnd != nullptr && pBufSize != nullptr)
    {
        FilterHwndList(pWnd, pBufSize);
    }

    return ntStat;
}


DLLExport_C HWND NTAPI HookedNtUserGetForegroundWindow()
{
    auto dNtUserGetForegroundWindow =
        exchange_data.lookup_trampoline<decltype(&HookedNtUserGetForegroundWindow)>("NtUserGetForegroundWindow");
    HWND Hwnd = dNtUserGetForegroundWindow();
    if (Hwnd != nullptr && IsWindowBad(Hwnd))
    {
        // TODO
        // Hwnd = (HWND)NtUserGetThreadState(THREADSTATE_ACTIVEWINDOW);
    }
    return Hwnd;
}