#include "plugin.h"
#include "scyllagui/scylla_app.h"
#include <stdexcept>
#include <memory>
#include <mutex>
using namespace std;


static unique_ptr<ScyllaGuiApp> app;
static std::thread app_ui_thread;
static std::condition_variable app_start_cond;
static std::mutex app_start_mutex;
static bool app_running = false;
static void ensure_scylla_app()
{
    if (app) {
        if (app->closed()) {
            dprintf("app closed\n");
        } else {
            dprintf("app still is alive\n");
            return;
        }
    }

    std::string config_file = "";
    if (app)
        config_file = app->config_file();

    if (app_ui_thread.joinable())
        app_ui_thread.join();

    app_ui_thread = std::thread([config_file]() {
        app = make_unique<ScyllaGuiApp>();

        if (!config_file.empty())
            app->open_file(config_file);

        while (!app->closed()) {
            if (!app_running) {
                unique_lock<mutex> lock(app_start_mutex);
                app_start_cond.wait(lock);

                if (!app_running)
                    break;
            }

            app->run_loop();
        }

        app_running = false;
        app = nullptr;
    });
}
static void scylla_app_show() {
    if (app && app->running())
        return;

    ensure_scylla_app();
    app_running = true;
    app_start_cond.notify_one();
}
static void scylla_app_close() {
    if (app) {
        const bool is_running = app->running();
        app->stop();

        if (!app->closed())
            app->close_window();

        if (app_ui_thread.joinable()) {
            if (!is_running) {
                app_running = false;
                app_start_cond.notify_one();
            }

            app_ui_thread.join();
        }
    }

    app_running = false;
}

enum ScyllaMenuItems : int {
    MENU_SHOW = 0,
    MENU_CLOSE,
    MENU_MAX
};

static void cbMenuEntry(CBTYPE cbType, void* callbackInfo) {
    PLUG_CB_MENUENTRY* info = (PLUG_CB_MENUENTRY*)callbackInfo;
    switch (info->hEntry)
    {
        case MENU_SHOW: {
            dprintf("show scyllamon window\n");
            scylla_app_show();
        } break;
        case MENU_CLOSE: {
            dprintf("close scyllamon window\n");
            scylla_app_close();
        } break;
        default:
            break;
    }
}

static void cbDebugloop(CBTYPE cbType, void* callbackInfo)
{
    PLUG_CB_DEBUGEVENT* d = (PLUG_CB_DEBUGEVENT*)callbackInfo;
    d->DebugEvent->dwProcessId;
}

//Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    try {
        dprintf("Initializing\n");
        ensure_scylla_app();
    } catch (const std::exception& e) {
        dprintf("%s\n", e.what());
        return false;
    }

    _plugin_registercallback(pluginHandle, CB_MENUENTRY, cbMenuEntry);
    _plugin_registercallback(pluginHandle, CB_DEBUGEVENT, cbDebugloop);

    return true; //Return false to cancel loading the plugin.
}

//Deinitialize your plugin data here.
void pluginStop()
{
    scylla_app_close();
}

//Do GUI/Menu related things here.
void pluginSetup()
{
    _plugin_menuaddentry(hMenu, MENU_SHOW, "&Show");
    _plugin_menuaddentry(hMenu, MENU_CLOSE, "&Close");
}
