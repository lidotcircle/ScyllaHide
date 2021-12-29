#include "logger/log_client.h"
#include "printf.h"

#define BUFSIZE (0xFFFF)
#define MIN_AB(a, b) ((a) < (b) ? (a) : (b))

static size_t strlen__(const char* str) {
    size_t len = 0;
    while (*str++)
        len++;
    return len;
}

static size_t strncpy__(char* dest, const char* src, size_t n) {
    size_t i = 0;
    while (i < n && src[i])
        dest[i++] = src[i];
    return i;
}

void LogClient::send_var(const char* prefix, const char* fmt, va_list args) {
    char buf[BUFSIZE];
    auto len = strlen__(prefix);
    auto off = MIN_AB(len,sizeof(buf));
    strncpy__(buf, prefix, off);

    auto n = vsnprintf_(buf + off, sizeof(buf) - off, fmt, args);
    this->send(buf, n + off);
}

void LogClient::send(const char* buf, uint16_t bufsize) {
}

void LogClient::sendfmt(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    this->send_var("", fmt, args);
    va_end(args);
}

void LogClient::info(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    this->send_var("INFO ", fmt, args);
    va_end(args);
}

void LogClient::warn(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    this->send_var("WARN ", fmt, args);
    va_end(args);
}

void LogClient::error(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    this->send_var("ERROR ", fmt, args);
    va_end(args);
}

LogClient::~LogClient() {
}