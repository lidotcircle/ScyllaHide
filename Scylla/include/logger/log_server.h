#ifndef _SCYLLA_LOG_SERVER_H_
#define _SCYLLA_LOG_SERVER_H_


class LogServer {
protected:
    virtual void consume_message(const char* buf, int bufsize) = 0;

public:
    virtual void poll() = 0;
    virtual void stop() = 0;
    virtual ~LogServer();
};


#endif // _SCYLLA_LOG_SERVER_H_