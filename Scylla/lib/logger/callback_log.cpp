#include "logger/callback_log.h"
#include <iostream>
#include <string>
using namespace std;


CallbackLog::CallbackLog(std::function<void(const char*, int, void*)> callback, void* data)
    : _callback(callback)
    , data(data)
{
}

void CallbackLog::consume_message(const char* msg, int len) {
    this->_callback(msg, len, this->data);
}
