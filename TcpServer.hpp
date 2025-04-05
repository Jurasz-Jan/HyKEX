#pragma once

#include "NetworkSocket.hpp"
#include <memory>
#include <string>

namespace quantum_shield {

class TcpServer {
public:
    TcpServer();
    ~TcpServer();

    // Bind to a port and start listening
    bool Start(int port);

    // Accept a pending connection. Returns a valid socket on success, or invalid on failure.
    // This is blocking by default.
    NetworkSocket Accept();

    void Stop();

private:
    NetworkSocket m_server_socket;
    int m_port = 0;
};

} // namespace quantum_shield
