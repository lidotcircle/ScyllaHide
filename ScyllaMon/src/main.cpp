#include "scyllagui/scylla_app.h"


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    ScyllaGuiApp app;

    app.run_loop();
    return 0;
}
