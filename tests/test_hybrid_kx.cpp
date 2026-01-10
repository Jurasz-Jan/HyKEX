#include <gtest/gtest.h>
#include "../HybridKeyExchange.hpp"

using namespace quantum_shield;

class HybridKeyExchangeTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize logic if needed
    }
};

// Test 1: Full Handshake Success
TEST_F(HybridKeyExchangeTest, HandshakeSuccess) {
    HybridKeyExchange client;
    HybridKeyExchange server;

    // 1. Client Hello
    ClientHello c_hello = client.GenerateClientHello();
    ASSERT_EQ(c_hello.pubkey_classic.size(), 32);
    ASSERT_EQ(c_hello.pubkey_quantum.size(), 1184); // Kyber 768 pubkey size

    // 2. Server Process
    auto s_hello_opt = server.ProcessClientHello(c_hello);
    ASSERT_TRUE(s_hello_opt.has_value());
    ServerHello s_hello = s_hello_opt.value();
    
    ASSERT_EQ(s_hello.status, 0x00);
    ASSERT_EQ(s_hello.pubkey_classic.size(), 32);
    ASSERT_EQ(s_hello.ciphertext_quantum.size(), 1088); // Kyber 768 CT size

    // 3. Client Process
    bool success = client.ProcessServerHello(s_hello);
    ASSERT_TRUE(success);

    // 4. Verify Keys
    std::vector<uint8_t> client_key = client.GetSessionKey();
    std::vector<uint8_t> server_key = server.GetSessionKey();

    ASSERT_FALSE(client_key.empty());
    ASSERT_FALSE(server_key.empty());
    ASSERT_EQ(client_key.size(), 32); // SHA256 output

    ASSERT_EQ(client_key, server_key);
}

// Test 2: Invalid Ciphertext (Tampering)
TEST_F(HybridKeyExchangeTest, TamperedCiphertext) {
    HybridKeyExchange client;
    HybridKeyExchange server;

    ClientHello c_hello = client.GenerateClientHello();
    auto s_hello_opt = server.ProcessClientHello(c_hello);
    ASSERT_TRUE(s_hello_opt.has_value());
    ServerHello s_hello = s_hello_opt.value();

    // Corrupt ciphertext
    s_hello.ciphertext_quantum[0] ^= 0xFF;

    // Client should fail either during KEM or derive a different key?
    // Kyber implicit rejection: produces random shared secret
    // So ProcessServerHello might SUCCEED (return true) but keys will mismatch
    // OR decaps returns error if it checks auth tag?
    // liboqs decaps usually returns OQS_SUCCESS even if implicit rejection happens, 
    // unless strictly checking. Let's see behavior.
    
    // UPDATE: OQS internal implementation logic for Kyber (ML-KEM) usually does implicit rejection.
    // So Decaps should succeed, but shared secret will be garbage.
    // Thus ProcessServerHello returns true, but keys differ.
    
    bool client_res = client.ProcessServerHello(s_hello);
    // If it returns true (implicit rejection), keys must not match.
    if (client_res) {
        std::vector<uint8_t> client_key = client.GetSessionKey();
        std::vector<uint8_t> server_key = server.GetSessionKey();
        ASSERT_NE(client_key, server_key);
    } else {
        // Explicit failure is also fine
        SUCCEED();
    }
}
