#include <gtest/gtest.h>
#include <thread>
#include <chrono>
#include "../TcpServer.hpp"
#include "../TcpClient.hpp"

using namespace quantum_shield;

class NetworkTest : public ::testing::Test {
protected:
    void SetUp() override {
    }
};

TEST_F(NetworkTest, LoopbackConnection) {
    const int TEST_PORT = 9999;
    bool server_received = false;
    std::vector<uint8_t> received_data;
    std::string test_msg = "Hello Quantum World";

    // Server Thread
    std::thread server_thread([&]() {
        TcpServer server;
        if (!server.Start(TEST_PORT)) return;
        
        NetworkSocket client_sock = server.Accept();
        if (client_sock.IsValid()) {
            std::vector<uint8_t> buffer;
            if (client_sock.ReceiveAll(buffer, test_msg.size())) {
                server_received = true;
                received_data = buffer;
            }
        }
    });

    // Give server time to bind
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Client
    TcpClient client;
    NetworkSocket conn = client.Connect("127.0.0.1", TEST_PORT);
    ASSERT_TRUE(conn.IsValid());

    std::vector<uint8_t> data(test_msg.begin(), test_msg.end());
    ASSERT_TRUE(conn.SendAll(data));

    if (server_thread.joinable()) {
        server_thread.join();
    }

    ASSERT_TRUE(server_received);
    std::string received_str(received_data.begin(), received_data.end());
    ASSERT_EQ(test_msg, received_str);
}
