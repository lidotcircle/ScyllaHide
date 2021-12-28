#include <stdio.h>
#include <Windows.h>
#include "imgui.h"
#include "scyllagui/imgui_app.h"
#include "scyllagui/splug/splug_view.h"
#include <string>
using namespace std;

static const char* ChooserFile(const char* filter) 
{
    static char syFile[MAX_PATH];
    size_t convertedChars = 0;
    OPENFILENAME sfn;

    ZeroMemory( &sfn , sizeof( sfn));
    sfn.lStructSize = sizeof ( sfn );
    sfn.hwndOwner = NULL ;
    sfn.lpstrFile = syFile ;
    sfn.lpstrFile[0] = '\0';
    sfn.nMaxFile = sizeof( syFile );
    sfn.lpstrFilter = filter;
    sfn.nFilterIndex =1;
    sfn.lpstrFileTitle = NULL ;
    sfn.nMaxFileTitle = 0 ;
    sfn.lpstrInitialDir=NULL;

    sfn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOVALIDATE | OFN_HIDEREADONLY;
    if (GetOpenFileName( &sfn ) != TRUE)
        return nullptr;

    return syFile;
}

class ScyllaAPP: public ImGuiAPP
{
private:
    unique_ptr<GuiSplugView> m_splugView;

protected:
    virtual int render_frame() override;

public:
    ScyllaAPP(): ImGuiAPP("Scylla Monitor") {
        try {
        auto node = YAML::LoadFile("scylla.yaml");
        this->m_splugView = make_unique<GuiSplugView>(node);
        } catch (exception& e) {
            MessageBox(NULL, e.what(), "Error", MB_OK);
        }
    }
};

int ScyllaAPP::render_frame() {
    static bool show_demo_window = true;
    static bool show_another_window = false;
    static float clear_color[4];

    auto& io = ImGui::GetIO();
    ImGui::SetNextWindowPos( ImVec2(0,0) );
    ImGui::SetNextWindowSize(ImVec2(io.DisplaySize.x, io.DisplaySize.y));

    bool b_openfile = false;
    bool b_savefile = false;
    bool b_saveas   = false;

    if (ImGui::Begin("MainWindow" , nullptr , 
                 ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
                 ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings | 
                 ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoScrollbar | 
                 ImGuiWindowFlags_NoScrollWithMouse |
                 ImGuiWindowFlags_NoBringToFrontOnFocus))
    {
        if (ImGui::BeginChild("FileMenu", ImVec2(0, 20), false, ImGuiWindowFlags_NoScrollbar))
        {
            if (ImGui::Button("Open")) {
                auto file = ChooserFile("YAML (*.yaml)\0*.yaml\0ALL Files (*.*)\0*.*\0");
                b_openfile = true;
            }
            ImGui::SameLine();
            if (ImGui::Button("Save")) {
                b_savefile = true;
            }
            ImGui::SameLine();
            if (ImGui::Button("Save As")) {
                b_saveas = true;
            }
            ImGui::EndChild();
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        ImGui::Spacing();

        if (ImGui::BeginChild("config", ImVec2(0, 0), false)) {
            this->m_splugView->show();
            ImGui::EndChild();
        }

        ImGui::End();
    }

    // 1. Show the big demo window (Most of the sample code is in ImGui::ShowDemoWindow()! You can browse its code to learn more about Dear ImGui!).
    if (show_demo_window)
        ImGui::ShowDemoWindow(&show_demo_window);

    // 2. Show a simple window that we create ourselves. We use a Begin/End pair to created a named window.
    {
        static float f = 0.0f;
        static int counter = 0;

        ImGui::Begin("Hello, world!");                          // Create a window called "Hello, world!" and append into it.

        ImGui::Text("This is some useful text.");               // Display some text (you can use a format strings too)
        ImGui::Checkbox("Demo 打开 Window", &show_demo_window);      // Edit bools storing our window open/close state
        ImGui::Checkbox("Another Window", &show_another_window);

        ImGui::SliderFloat("float", &f, 0.0f, 1.0f);            // Edit 1 float using a slider from 0.0f to 1.0f
        ImGui::ColorEdit3("clear color", (float*)&clear_color); // Edit 3 floats representing a color

        if (ImGui::Button("Button"))                            // Buttons return true when clicked (most widgets return true when edited/activated)
            counter++;
        ImGui::SameLine();
        ImGui::Text("counter = %d", counter);

        ImGui::Text("Application average %.3f ms/frame (%.1f FPS)", 1000.0f / ImGui::GetIO().Framerate, ImGui::GetIO().Framerate);
        ImGui::End();
    }

    // 3. Show another simple window.
    if (show_another_window)
    {
        ImGui::Begin("Another Window", &show_another_window);   // Pass a pointer to our bool variable (the window will have a closing button that will clear the bool when clicked)
        ImGui::Text("Hello from another window!");
        if (ImGui::Button("Close Me"))
            show_another_window = false;
        ImGui::End();
    }

    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    ScyllaAPP app;

    app.run_loop();
    return 0;
}
