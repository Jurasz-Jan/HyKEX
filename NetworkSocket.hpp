#pragma once

#include <vector>
#include <string>
#include <stdexcept>
#include <iostream>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "Ws2_32.lib")
    using SocketHandle = SOCKET;
    #define INVALID_SOCKET_VAL INVALID_SOCKET
    #define CLOSE_SOCKET closesocket
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <unistd.h>
    #include <arpa/inet.h>
    using SocketHandle = int;
    #define INVALID_SOCKET_VAL -1
    #define CLOSE_SOCKET close
#endif

namespace quantum_shield {

class NetworkSocket {
public:
    NetworkSocket() : m_sockfd(INVALID_SOCKET_VAL) {}
    
    explicit NetworkSocket(SocketHandle fd) : m_sockfd(fd) {}

    ~NetworkSocket() {
        Close();
    }

    // Move-only semantics (RAII)
    NetworkSocket(const NetworkSocket&) = delete;
    NetworkSocket& operator=(const NetworkSocket&) = delete;

    NetworkSocket(NetworkSocket&& other) noexcept : m_sockfd(other.m_sockfd) {
        other.m_sockfd = INVALID_SOCKET_VAL;
    }

    NetworkSocket& operator=(NetworkSocket&& other) noexcept {
        if (this != &other) {
            Close();
            m_sockfd = other.m_sockfd;
            other.m_sockfd = INVALID_SOCKET_VAL;
        }
        return *this;
    }

    bool IsValid() const {
        return m_sockfd != INVALID_SOCKET_VAL;
    }

    void Close() {
        if (IsValid()) {
            CLOSE_SOCKET(m_sockfd);
            m_sockfd = INVALID_SOCKET_VAL;
        }
    }

    // Send exact amount of data
    bool SendAll(const std::vector<uint8_t>& data) {
        if (!IsValid()) return false;
        
        size_t total_sent = 0;
        size_t bytes_left = data.size();
        
        while (total_sent < data.size()) {
            #ifdef _WIN32
            int sent = send(m_sockfd, reinterpret_cast<const char*>(data.data() + total_sent), (int)bytes_left, 0);
            #else
            ssize_t sent = send(m_sockfd, data.data() + total_sent, bytes_left, 0);
            #endif

            if (sent == -1) {
                return false;
            }
            total_sent += sent;
            bytes_left -= sent;
        }
        return true;
    }

    // Receive exact amount of data (blocking)
    bool ReceiveAll(std::vector<uint8_t>& buffer, size_t size) {
        if (!IsValid()) return false;
        
        buffer.resize(size);
        size_t total_received = 0;
        size_t bytes_left = size;

        while (total_received < size) {
            #ifdef _WIN32
            int recvd = recv(m_sockfd, reinterpret_cast<char*>(buffer.data() + total_received), (int)bytes_left, 0);
            #else
            ssize_t recvd = recv(m_sockfd, buffer.data() + total_received, bytes_left, 0);
            #endif

            if (recvd <= 0) { // 0 = closed, -1 = error
                return false;
            }
            total_received += recvd;
            bytes_left -= recvd;
        }
        return true;
    }

    SocketHandle GetHandle() const { return m_sockfd; }

private:
    SocketHandle m_sockfd;
};

// Global init for Winsock (No-op on Linux)
class SocketSystem {
public:
    static void Initialize() {
        #ifdef _WIN32
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            throw std::runtime_error("WSAStartup failed");
        }
        #endif
    }

    static void Cleanup() {
        #ifdef _WIN32
        WSACleanup();
        #endif
    }
};

} // namespace quantum_shield
