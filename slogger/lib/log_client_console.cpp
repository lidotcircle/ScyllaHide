#include "logger/log_client_console.h"
#include <stdio.h>


void LogClientConsole::send(const char* buf, uint16_t bufsize)
{
    printf("%s", buf);
}