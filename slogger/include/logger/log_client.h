#ifndef _SCYLLA_LOG_CLIENT_H_
#define _SCYLLA_LOG_CLIENT_H_

#include <stdint.h>
#include <stdarg.h>


class LogClient {
protected:
    void send_var(const char* prefix, const char* fmt, va_list args);

public:
    virtual void send(const char* buf, uint16_t bufsize);

    void sendfmt(const char* fmt, ...);
    void info (const char* fmt, ...);
    void warn (const char* fmt, ...);
    void error(const char* fmt, ...);

    virtual ~LogClient();
};

#endif // _SCYLLA_LOG_CLIENT_H_