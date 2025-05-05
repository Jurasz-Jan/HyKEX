#include "TcpServer.hpp"
#include <iostream>

namespace quantum_shield {

TcpServer::TcpServer() {
    SocketSystem::Initialize();
}

TcpServer::~TcpServer() {
    Stop();
    SocketSystem::Cleanup(); // Note: Global cleanup might be tricky if multiple objects exist. 
                             // Ideally, SocketSystem would be a singleton or managed by main.
}

bool TcpServer::Start(int port) {
    m_port = port;

    // Create socket
    #ifdef _WIN32
    SocketHandle fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    #else
    SocketHandle fd = socket(AF_INET, SOCK_STREAM, 0);
    #endif

    if (fd == INVALID_SOCKET_VAL) {
        std::cerr << "Failed to create socket" << std::endl;
        return false;
    }

    m_server_socket = NetworkSocket(fd);

    // Reuse address
    int opt = 1;
    #ifdef _WIN32
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    #else
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    #endif

    // Bind
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "Bind failed" << std::endl;
        return false;
    }

    // Listen
    if (listen(fd, 3) < 0) {
        std::cerr << "Listen failed" << std::endl;
        return false;
    }

    std::cout << "Server listening on port " << port << std::endl;
    return true;
}

NetworkSocket TcpServer::Accept() {
    if (!m_server_socket.IsValid()) {
        return NetworkSocket();
    }

    sockaddr_in client_addr{};
    #ifdef _WIN32
    int addrlen = sizeof(client_addr);
    #else
    socklen_t addrlen = sizeof(client_addr);
    #endif

    SocketHandle client_fd = accept(m_server_socket.GetHandle(), (struct sockaddr*)&client_addr, &addrlen);
    
    if (client_fd == INVALID_SOCKET_VAL) {
        std::cerr << "Accept failed" << std::endl;
        return NetworkSocket();
    }

    // Optional: Print client IP
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), ip, INET_ADDRSTRLEN);
    std::cout << "Connection accepted from " << ip << std::endl;

    return NetworkSocket(client_fd);
}

void TcpServer::Stop() {
    m_server_socket.Close();
}

} // namespace quantum_shield
