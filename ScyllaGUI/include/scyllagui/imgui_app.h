#ifndef _IMGUI_APP_H_
#define _IMGUI_APP_H_

#include <string>


class ImGuiAPP
{
private:
    bool m_run;
    std::string m_title;

protected:
    virtual int render_frame() = 0;
    
public:
    ImGuiAPP(std::string title);

    void run_loop();
    void stop();
};

#endif // _IMGUI_APP_H_