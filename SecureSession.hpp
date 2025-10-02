#pragma once

#include "NetworkSocket.hpp"
#include "HybridKeyExchange.hpp"
#include "Protocol.hpp"
#include <vector>
#include <optional>

namespace quantum_shield {

class SecureSession {
public:
    explicit SecureSession(NetworkSocket socket);

    // Client Side Handshake
    bool HandshakeAsClient();

    // Server Side Handshake
    bool HandshakeAsServer();

    // Send data encrypted with AES-256-GCM
    bool SendEncrypted(const std::string& plaintext);

    // Receive and decrypt data
    std::optional<std::string> ReceiveEncrypted();

    bool IsEstablished() const { return !m_session_key.empty(); }

private:
    NetworkSocket m_socket;
    HybridKeyExchange m_kex;
    std::vector<uint8_t> m_session_key;

    // Helper to send protocol messages
    bool SendMessage(MsgType type, const std::vector<uint8_t>& payload);
    
    // Helper to receive specific protocol messages
    std::optional<std::vector<uint8_t>> ReceiveMessage(MsgType expected_type);

    // Low-level AES-GCM
    std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& plaintext);
    std::optional<std::vector<uint8_t>> Decrypt(const std::vector<uint8_t>& ciphertext, 
                                                const std::vector<uint8_t>& iv, 
                                                const std::vector<uint8_t>& tag);
};

} // namespace quantum_shield
