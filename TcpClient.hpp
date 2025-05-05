#pragma once

#include "NetworkSocket.hpp"
#include <string>

namespace quantum_shield {

class TcpClient {
public:
    TcpClient();
    ~TcpClient();

    // Connect to a server. Returns a valid socket for communication on success.
    // The returned socket is *moved* out of the client utility class (simplification).
    // Or we can keep it internal. Let's return it to be symmetric with Server::Accept().
    NetworkSocket Connect(const std::string& host, int port);

private:
};

} // namespace quantum_shield
