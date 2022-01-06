#include "plugin.h"
#include "scyllagui/scylla_app.h"
#include "scyllagui/widget/checkbox_list.h"
#include "scylla/utils.h"
#include <stdexcept>
#include <memory>
#include <tuple>
#include <mutex>
using namespace std;

#define x64DBG_CONFIG_ENTRY "x64dbg_plug"


static string default_config_path = "";
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
        app = make_unique<ScyllaGuiApp>(true);

        if (config_file.empty()) {
            if (!default_config_path.empty() && app->config_file().empty())
                app->open_file(default_config_path);
        } else {
            app->open_file(config_file);
        }

        auto node = app->config_node();
        if (node.IsNull())
            node["__"] = "";

        vector<tuple<string,string,bool>> x64dbg_config = {
            { "enable", "启用", true },
        };
        auto x64dbg_config_node = node[x64DBG_CONFIG_ENTRY];
        auto checkbox_list = make_unique<CheckboxList>(x64dbg_config_node, move(x64dbg_config));
        app->add_collapsing_config(x64DBG_CONFIG_ENTRY, "x64dbg配置", move(checkbox_list));

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

static bool caught_systembp = false;
static void cbDebugloop(CBTYPE cbType, void* callbackInfo)
{
    PLUG_CB_DEBUGEVENT* d = (PLUG_CB_DEBUGEVENT*)callbackInfo;
    auto& de = *d->DebugEvent;

    if (de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
        caught_systembp = false;
        ensure_scylla_app();
        dprintf("new process pid = %d\n", de.dwProcessId);
        app->set_pid(de.dwProcessId);
    }
    else if (!caught_systembp && de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
        if (de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
            dprintf("caught system breakpoint, doit\n");
            caught_systembp = true;
            ensure_scylla_app();
            auto node = app->dump_node();
            auto x64dbg_config_node = node[x64DBG_CONFIG_ENTRY];
            if (!x64dbg_config_node["enable"].as<bool>())
                return;

            if (app->operation_doit()) {
                dprintf("doit done\n");
            } else {
                dprintf("doit failed\n");
            }
        }
    }
}

static void cbDetach(CBTYPE cbType, void* callbackInfo)
{
    ensure_scylla_app();
    app->set_pid(0);
}

static void cbStopDbg(CBTYPE cbType, void* callbackInfo)
{
    ensure_scylla_app();
    app->set_pid(0);
}

static bool FileExists(LPCTSTR szPath)
{
  DWORD dwAttrib = GetFileAttributes(szPath);

  return (dwAttrib != INVALID_FILE_ATTRIBUTES && 
         !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

//Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    default_config_path = initStruct->pluginName;
    default_config_path.erase(default_config_path.find_last_of('\\') + 1);
    default_config_path += "scylla.yaml";
    if (!FileExists(default_config_path.c_str()))
        default_config_path = "";

    try {
        dprintf("Initializing\n");
        ensure_scylla_app();
    } catch (const std::exception& e) {
        dprintf("%s\n", e.what());
        return false;
    }

    _plugin_registercallback(pluginHandle, CB_MENUENTRY, cbMenuEntry);
    _plugin_registercallback(pluginHandle, CB_DEBUGEVENT, cbDebugloop);
    _plugin_registercallback(pluginHandle, CB_DETACH, cbDetach);
    _plugin_registercallback(pluginHandle, CB_STOPDEBUG, cbStopDbg);

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
