#include "TcpClient.hpp"
#include <iostream>

namespace quantum_shield {

TcpClient::TcpClient() {
    SocketSystem::Initialize();
}

TcpClient::~TcpClient() {
    SocketSystem::Cleanup();
}

NetworkSocket TcpClient::Connect(const std::string& host, int port) {
    #ifdef _WIN32
    SocketHandle fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    #else
    SocketHandle fd = socket(AF_INET, SOCK_STREAM, 0);
    #endif

    if (fd == INVALID_SOCKET_VAL) {
        std::cerr << "Failed to create socket" << std::endl;
        return NetworkSocket();
    }

    NetworkSocket sock(fd); // Wrap quickly for RAII

    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host.c_str(), &serv_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address/ Address not supported" << std::endl;
        return NetworkSocket();
    }

    if (connect(fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection Failed" << std::endl;
        return NetworkSocket();
    }

    std::cout << "Connected to " << host << ":" << port << std::endl;
    
    // We want to return the socket wrapper.
    // Since we created 'sock' on stack, we can move it out.
    return std::move(sock);
}

} // namespace quantum_shield
