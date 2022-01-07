#ifndef _SCYLLA_CONSTANTS_H_
#define _SCYLLA_CONSTANTS_H_

/**
 * represent the default anti-anti-debug hook library in this project
 */
#define ANTIANTI_DLL "antianti.dll"
#define ANTIANTI_DLL_EXCHANGE_SYMBOL "exchange_data"

/**
 * represent the default monitoring hook library in this project
 */
#define MONITORING_DLL "monitoring.dll"
#define MONITORING_DLL_EXCHANGE_SYMBOL "exchange_data"

/**
 * hook target start with this prefix should be ignored
 */
#define INLINE_HOOK_DISABLE_PREFIX "//"

/**
 * inline hook remark separator
 */
#define INLINE_HOOK_REMARK_SEPARATOR "//"

#endif // _SCYLLA_CONSTANTS_H_