#include <Windows.h>
#include <iostream>
using namespace std;


int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    auto h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    char buf[0x100];

    bool cont = true;
    do {
        cont = MessageBoxA(0, "ClickMe", "En...", MB_OKCANCEL) == IDCANCEL;
        cout << "read => alloc => write" << endl;
        ReadProcessMemory(h, WinMain, buf, sizeof(buf), 0);
        auto ab = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        WriteProcessMemory(h, ab, buf, sizeof(buf), 0);
    } while (cont);

    cout << "exit" << endl;
    return 0;
}