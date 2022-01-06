#ifndef _IMGUI_APP_H_
#define _IMGUI_APP_H_

#include <string>
#include <Windows.h>


class ImGuiAPP
{
private:
    bool m_run;
    std::string m_title;
    float m_default_width;
    float m_default_height;
    bool  m_shown;
    bool  m_closed;
    WNDCLASSEX m_wcls;
    HWND m_hwnd;

protected:
    virtual int render_frame() = 0;
    virtual void window_show();
    virtual void window_hide();
    static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
    
public:
    ImGuiAPP(std::string title, float default_width, float default_height);

    void run_loop();
    void stop();

    void disable_resize();
    void close_window();

    bool running() const;
    bool shown() const;
    bool closed() const;

    virtual ~ImGuiAPP();
};

#endif // _IMGUI_APP_H_