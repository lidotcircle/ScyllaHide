#include "internal_dlls.h"
#include "hook_library.h"
#include "monitor_library.h"

#define INTERNAL_DLL_LIST \
    IENTRY("hook_library.h",    hook_library,    sizeof(hook_library),    "antianti.dll",   "exchange_data") \
    IENTRY("monitor_library.h", monitor_library, sizeof(monitor_library), "monitoring.dll", "exchange_data")


const std::vector<InternalDLLInfo> internal_dlls = {
#define IENTRY(cheader, data, size, dllname, exch_symbol) InternalDLLInfo{ data, size, dllname, exch_symbol },
INTERNAL_DLL_LIST
#undef IENTRY
};