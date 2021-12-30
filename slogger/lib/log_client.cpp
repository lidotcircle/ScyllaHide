#include <Windows.h>
#include "logger/log_client.h"
#include <stdio.h>
#include <string.h>
#include "printf.h"

#define BUFSIZE (0xFFFF)
#define MIN_AB(a, b) ((a) < (b) ? (a) : (b))

static decltype(wvsprintfA)*  fwvsprintfA  = nullptr;
static int fvsprintf(char* buf, const char* fmt, va_list arg) {
    if (fwvsprintfA == nullptr)
        fwvsprintfA = (decltype(fwvsprintfA))GetProcAddress(GetModuleHandleA("user32.dll"), "wvsprintfA");
    
    if (!fwvsprintfA)
        return 0;

    return fwvsprintfA(buf, fmt, arg);
}

void LogClient::send_var(const char* prefix, const char* fmt, va_list args) {
    char buf[BUFSIZE];
    auto len = strlen(prefix);
    auto off = MIN_AB(len,sizeof(buf));
    strncpy(buf, prefix, off);

    // auto n = vsnprintf(buf + off, sizeof(buf) - off, fmt, args);
    // auto n = vsnprintf_(buf + off, sizeof(buf) - off, fmt, args);
    auto n = fvsprintf(buf + off, fmt, args);
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