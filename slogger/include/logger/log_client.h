#ifndef _SCYLLA_LOG_CLIENT_H_
#define _SCYLLA_LOG_CLIENT_H_

#include <stdint.h>
#include <stdarg.h>

#undef FORMAT_STRING
#if _MSC_VER >= 1400
# include <sal.h>
# if _MSC_VER > 1400
#  define FORMAT_STRING(p) _Printf_format_string_ p
# else
#  define FORMAT_STRING(p) __format_string p
# endif /* FORMAT_STRING */
#else
# define FORMAT_STRING(p) p
#endif /* _MSC_VER */


class LogClient {
protected:
    void send_var(const char* prefix, const char* fmt, va_list args);

public:
    virtual void send(const char* buf, uint16_t bufsize);

    void sendfmt(FORMAT_STRING(const char* fmt), ...);
    void info (FORMAT_STRING(const char* fmt), ...);
    void warn (FORMAT_STRING(const char* fmt), ...);
    void error(FORMAT_STRING(const char* fmt), ...);

    virtual ~LogClient();
};

#endif // _SCYLLA_LOG_CLIENT_H_