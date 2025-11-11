#include <iostream>
#include <openssl/opensslv.h>
#include <oqs/kem.h>
#include <string>
#include <vector>

#include "TcpServer.hpp"
#include "TcpClient.hpp"
#include "SecureSession.hpp"

using namespace quantum_shield;

void RunServer(int port) {
    TcpServer server;
    if (!server.Start(port)) return;

    while (true) {
        std::cout << "Waiting for connections..." << std::endl;
        NetworkSocket client_sock = server.Accept();
        if (client_sock.IsValid()) {
            SecureSession session(std::move(client_sock));
            if (session.HandshakeAsServer()) {
                // Read one message and echo
                auto msg = session.ReceiveEncrypted();
                if (msg) {
                    std::cout << "Received: " << *msg << std::endl;
                    session.SendEncrypted("Echo: " + *msg);
                }
            } else {
                std::cerr << "Handshake failed." << std::endl;
            }
        }
    }
}

void RunClient(const std::string& host, int port) {
    TcpClient client;
    NetworkSocket sock = client.Connect(host, port);
    if (!sock.IsValid()) return;

    SecureSession session(std::move(sock));
    if (session.HandshakeAsClient()) {
        std::string secret = "This is a super secret quantum message!";
        session.SendEncrypted(secret);
        std::cout << "Sent: " << secret << std::endl;

        auto reply = session.ReceiveEncrypted();
        if (reply) {
            std::cout << "Server Reply: " << *reply << std::endl;
        }
    } else {
        std::cerr << "Handshake failed." << std::endl;
    }
}

#include "Benchmark.hpp"

// ... existing includes ...

int main(int argc, char* argv[]) {
    // Usage: 
    // ./quantum_shield --server 9999
    // ./quantum_shield --client 127.0.0.1 9999
    // ./quantum_shield --benchmark <iterations>

    std::vector<std::string> args(argv, argv + argc);
    
    if (argc >= 3 && args[1] == "--benchmark") {
        int iterations = std::stoi(args[2]);
        Benchmark bench;
        bench.Run(iterations, "benchmark_results.csv");
        return 0;
    }

    if (argc >= 3 && args[1] == "--server") {
        int port = std::stoi(args[2]);
        RunServer(port);
        return 0;
    } 
    if (argc >= 4 && args[1] == "--client") {
        std::string host = args[2];
        int port = std::stoi(args[3]);
        RunClient(host, port);
        return 0;
    }

    std::cout << "Quantum-Shield 6G: Post-Quantum Cryptography System" << std::endl;
    std::cout << "Usage:" << std::endl;
    std::cout << "  --server <port>" << std::endl;
    std::cout << "  --client <host> <port>" << std::endl;
    std::cout << "  --benchmark <iterations>" << std::endl;
    
    // Check liboqs
    OQS_init();
    if (OQS_KEM_alg_is_enabled(OQS_KEM_alg_ml_kem_768)) {
         std::cout << " - ML-KEM-768: ENABLED" << std::endl;
    }
    OQS_destroy();

    return 0;
}
