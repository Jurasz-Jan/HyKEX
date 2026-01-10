#include <gtest/gtest.h>
#include <thread>
#include <chrono>
#include "../TcpServer.hpp"
#include "../TcpClient.hpp"
#include "../SecureSession.hpp"

using namespace quantum_shield;

class SecureSessionTest : public ::testing::Test {
protected:
    void SetUp() override {
    }
};

TEST_F(SecureSessionTest, FullEncryptedHandshake) {
    const int TEST_PORT = 9998;
    bool server_success = false;
    std::string received_msg;
    std::string server_reply = "Quantum Secured Reply";
    
    // Server Thread
    std::thread server_thread([&]() {
        TcpServer server;
        if (!server.Start(TEST_PORT)) return;
        
        NetworkSocket client_sock = server.Accept();
        if (client_sock.IsValid()) {
            SecureSession session(std::move(client_sock));
            if (session.HandshakeAsServer()) {
                auto msg = session.ReceiveEncrypted();
                if (msg) {
                    received_msg = *msg;
                    // Echo back
                    session.SendEncrypted(server_reply);
                    server_success = true;
                }
            }
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Client Code
    TcpClient client;
    NetworkSocket conn = client.Connect("127.0.0.1", TEST_PORT);
    ASSERT_TRUE(conn.IsValid());

    SecureSession session(std::move(conn));
    ASSERT_TRUE(session.HandshakeAsClient());
    
    std::string secret = "Top Secret Payload";
    ASSERT_TRUE(session.SendEncrypted(secret));

    auto reply = session.ReceiveEncrypted();
    ASSERT_TRUE(reply.has_value());
    ASSERT_EQ(*reply, server_reply);

    if (server_thread.joinable()) {
        server_thread.join();
    }

    ASSERT_TRUE(server_success);
    ASSERT_EQ(received_msg, secret);
}
