#include "internal_dlls.h"
#include "antianti_library.h"
#include "monitor_library.h"
#include "iat_monitor_library.h"

#define INTERNAL_DLL_LIST \
    IENTRY("antianti_library.h", antianti_library, sizeof(antianti_library), "antianti.dll",   "exchange_data") \
    IENTRY("monitor_library.h",  monitor_library,  sizeof(monitor_library),  "monitoring.dll", "exchange_data") \
    IENTRY("iat_monitor_library.h", iat_monitor_library,  sizeof(iat_monitor_library),  "iathookmon.dll", "exchange_data")


const std::vector<InternalDLLInfo> internal_dlls = {
#define IENTRY(cheader, data, size, dllname, exch_symbol) InternalDLLInfo{ data, size, dllname, exch_symbol },
INTERNAL_DLL_LIST
#undef IENTRY
};