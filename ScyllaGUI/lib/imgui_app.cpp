#include <Windows.h>
#include "imgui.h"
#include "imgui_impl_dx9.h"
#include "imgui_impl_win32.h"
#include "scyllagui/imgui_app.h"
#include <d3d9.h>
#include <tchar.h>
#include <string>
#include <vector>
#include <map>
#include <stdexcept>
using namespace std;
#pragma comment(lib, "d3d9.lib")

static map<HWND,ImGuiAPP*> hwnd2apps;
static void add_imguiapp(HWND hwnd, ImGuiAPP* app)
{
    if (hwnd2apps.find(hwnd) != hwnd2apps.end())
        throw runtime_error("hwnd2apps already contains hwnd");

    hwnd2apps[hwnd] = app;
}
static void remove_imguiapp(HWND hwnd)
{
    if (hwnd2apps.find(hwnd) == hwnd2apps.end())
        throw runtime_error("hwnd2apps does not contain hwnd");

    hwnd2apps.erase(hwnd);
}
static ImGuiAPP* get_imguiapp(HWND hwnd)
{
    if (hwnd2apps.find(hwnd) == hwnd2apps.end())
        return nullptr;

    return hwnd2apps[hwnd];
}

static bool FileExists(LPCTSTR szPath)
{
  DWORD dwAttrib = GetFileAttributes(szPath);

  return (dwAttrib != INVALID_FILE_ATTRIBUTES && 
         !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

// Data
static LPDIRECT3D9              g_pD3D = NULL;
static LPDIRECT3DDEVICE9        g_pd3dDevice = NULL;
static D3DPRESENT_PARAMETERS    g_d3dpp = {};


// Helper functions
static bool CreateDeviceD3D(HWND hWnd)
{
    if ((g_pD3D = Direct3DCreate9(D3D_SDK_VERSION)) == NULL)
        return false;

    // Create the D3DDevice
    ZeroMemory(&g_d3dpp, sizeof(g_d3dpp));
    g_d3dpp.Windowed = TRUE;
    g_d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    g_d3dpp.BackBufferFormat = D3DFMT_UNKNOWN; // Need to use an explicit format with alpha if needing per-pixel alpha composition.
    g_d3dpp.EnableAutoDepthStencil = TRUE;
    g_d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
    g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_ONE;           // Present with vsync
    //g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_IMMEDIATE;   // Present without vsync, maximum unthrottled framerate
    if (g_pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hWnd, D3DCREATE_HARDWARE_VERTEXPROCESSING, &g_d3dpp, &g_pd3dDevice) < 0)
        return false;

    return true;
}

static void CleanupDeviceD3D()
{
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = NULL; }
    if (g_pD3D) { g_pD3D->Release(); g_pD3D = NULL; }
}

static void ResetDevice()
{
    ImGui_ImplDX9_InvalidateDeviceObjects();
    HRESULT hr = g_pd3dDevice->Reset(&g_d3dpp);
    if (hr == D3DERR_INVALIDCALL)
        IM_ASSERT(0);
    ImGui_ImplDX9_CreateDeviceObjects();
}

// Forward declare message handler from imgui_impl_win32.cpp
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Win32 message handler
/* static */
LRESULT WINAPI ImGuiAPP::WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED)
        {
            g_d3dpp.BackBufferWidth = LOWORD(lParam);
            g_d3dpp.BackBufferHeight = HIWORD(lParam);
            ResetDevice();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
            return 0;
        break;
    
    case WM_SHOWWINDOW: {
        auto app = get_imguiapp(hWnd);
        if (app) {
            if (wParam == TRUE) {
                app->window_show();
            } else {
                app->window_hide();
            }
        }
    } break;
    case WM_DESTROY: {
        auto app = get_imguiapp(hWnd);
        if (!app) {
            ::PostQuitMessage(0);
            return 0;
        } else {
            app->m_closed = true;
            app->m_run = false;
        }
    } break;
    }
    return ::DefWindowProc(hWnd, msg, wParam, lParam);
}


void ImGuiAPP::run_loop() {
    if (this->m_closed)
        throw runtime_error("ImGuiAPP::run_loop() called in closed state");

    this->m_run = true;
    auto& hwnd = this->m_hwnd;
    ImGuiIO& io = ImGui::GetIO();

    // Show the window
    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    while (this->m_run)
    {
        // Poll and handle messages (inputs, window resize, etc.)
        // You can read the io.WantCaptureMouse, io.WantCaptureKeyboard flags to tell if dear imgui wants to use your inputs.
        // - When io.WantCaptureMouse is true, do not dispatch mouse input data to your main application.
        // - When io.WantCaptureKeyboard is true, do not dispatch keyboard input data to your main application.
        // Generally you may always pass all inputs to dear imgui, and hide them from your application based on those two flags.
        MSG msg;
        while (::PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE))
        {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
        }
        if (!this->m_run)
            break;

        // Start the Dear ImGui frame
        ImGui_ImplDX9_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        if (this->m_shown && this->render_frame() != 0) {
            this->m_run = false;
            break;
        }

        // Rendering
        ImGui::EndFrame();
        g_pd3dDevice->SetRenderState(D3DRS_ZENABLE, FALSE);
        g_pd3dDevice->SetRenderState(D3DRS_ALPHABLENDENABLE, FALSE);
        g_pd3dDevice->SetRenderState(D3DRS_SCISSORTESTENABLE, FALSE);
        D3DCOLOR clear_col_dx = D3DCOLOR_RGBA((int)(0.45*255.0f), (int)(0.55*255.0f), (int)(0.60*255.0f), (int)(1.00*255.0f));
        g_pd3dDevice->Clear(0, NULL, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, clear_col_dx, 1.0f, 0);
        if (g_pd3dDevice->BeginScene() >= 0)
        {
            ImGui::Render();
            ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
            g_pd3dDevice->EndScene();
        }
 
         // Update and Render additional Platform Windows
        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault();
        }

        HRESULT result = g_pd3dDevice->Present(NULL, NULL, NULL, NULL);

        // Handle loss of D3D9 device
        if (result == D3DERR_DEVICELOST && g_pd3dDevice->TestCooperativeLevel() == D3DERR_DEVICENOTRESET)
            ResetDevice();
    }
}

void ImGuiAPP::stop() {
    this->m_run = false;
}

ImGuiAPP::ImGuiAPP(string title, float default_width, float default_height):
    m_title(title), m_default_width(default_width), m_default_height(default_height),
    m_run(false), m_shown(false), m_closed(true)
{
    // Create application window
    // ImGui_ImplWin32_EnableDpiAwareness();
    this->m_hwnd = NULL;
    auto& wc = this->m_wcls;
    auto& hwnd = this->m_hwnd;
    wc = { sizeof(WNDCLASSEX), CS_CLASSDC, ImGuiAPP::WndProc, 0L, 0L, GetModuleHandle(NULL), NULL, NULL, NULL, NULL, "ImGui APP", NULL };
    ::RegisterClassEx(&wc);
    hwnd = ::CreateWindow(
        wc.lpszClassName, this->m_title.c_str(), WS_OVERLAPPEDWINDOW,
        100, 100, this->m_default_width, this->m_default_height,
        NULL, NULL, wc.hInstance, NULL);
    add_imguiapp(hwnd, this);
    this->m_closed = false;

    // Initialize Direct3D
    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        ::UnregisterClass(wc.lpszClassName, wc.hInstance);
        throw runtime_error("Failed to create Direct3D device");
    }

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;       // Enable Keyboard Controls
    // io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;      // Enable Gamepad Controls
    // io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;         // Enable Docking
    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;         // Enable Multi-Viewport / Platform Windows

    // Setup Dear ImGui style
    ImGui::StyleColorsDark();
    //ImGui::StyleColorsClassic();

    // Setup Platform/Renderer backends
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX9_Init(g_pd3dDevice);

    vector<string> font_list = {
        "c:\\Windows\\Fonts\\msyh.ttc",
        "c:\\Windows\\Fonts\\msyh.ttf",
    };

    for (auto& font: font_list) {
        if (FileExists(font.c_str())) {
            io.Fonts->AddFontFromFileTTF(font.c_str(), 16.0f, NULL, io.Fonts->GetGlyphRangesChineseFull());
            break;
        }
    }
}

ImGuiAPP::~ImGuiAPP()
{
    ImGui_ImplDX9_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    if (this->m_hwnd != NULL) {
        ::DestroyWindow(this->m_hwnd);
        remove_imguiapp(this->m_hwnd);
        this->m_hwnd = NULL;
    }
    ::UnregisterClass(this->m_wcls.lpszClassName, this->m_wcls.hInstance);
}

void ImGuiAPP::disable_resize() {
    if (this->closed())
        return;
    
    auto style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX;
    SetWindowLong(this->m_hwnd, GWL_STYLE, style);
}

void ImGuiAPP::close_window() {
    PostMessageA(this->m_hwnd, WM_CLOSE, 0, 0);
}

bool ImGuiAPP::running() const { return this->m_run; }
bool ImGuiAPP::closed() const { return this->m_closed; }
bool ImGuiAPP::shown() const { return this->m_shown; }

void ImGuiAPP::window_show() {
    this->m_shown = true;
}

void ImGuiAPP::window_hide() {
    this->m_shown = false;
}
