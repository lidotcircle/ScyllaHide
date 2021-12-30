#include "logger/console_log.h"
#include <iostream>
#include <string>
using namespace std;


void ConsoleLog::consume_message(const char* msg, int len) {
    string s(msg, len);
    cout << s << endl;
}
