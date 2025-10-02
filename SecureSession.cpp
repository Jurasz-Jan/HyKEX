#include "SecureSession.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <cstring>

namespace quantum_shield {

constexpr size_t GCM_IV_SIZE = 12;
constexpr size_t GCM_TAG_SIZE = 16;

SecureSession::SecureSession(NetworkSocket socket) 
    : m_socket(std::move(socket)) {}

bool SecureSession::SendMessage(MsgType type, const std::vector<uint8_t>& payload) {
    if (payload.size() > 10 * 1024 * 1024) return false; // Safety limit 10MB

    std::vector<uint8_t> header = ProtocolUtils::SerializeHeader(type, static_cast<uint32_t>(payload.size()));
    if (!m_socket.SendAll(header)) return false;
    if (!payload.empty()) {
        if (!m_socket.SendAll(payload)) return false;
    }
    return true;
}

std::optional<std::vector<uint8_t>> SecureSession::ReceiveMessage(MsgType expected_type) {
    // Read Header
    std::vector<uint8_t> header_buf;
    if (!m_socket.ReceiveAll(header_buf, HEADER_SIZE)) return std::nullopt;

    ProtocolHeader header = ProtocolUtils::DeserializeHeader(header_buf);
    
    // Check type (unless we allow flexibility, but for handshake we are strict)
    if (header.type != expected_type && expected_type != MsgType::ERROR) {
        std::cerr << "Unexpected message type: " << (int)header.type << std::endl;
        return std::nullopt;
    }

    if (header.length > 10 * 1024 * 1024) { // Safety limit
        std::cerr << "Message too large" << std::endl;
        return std::nullopt;
    }

    // Read Payload
    std::vector<uint8_t> payload;
    if (header.length > 0) {
        if (!m_socket.ReceiveAll(payload, header.length)) return std::nullopt;
    }

    return payload;
}

bool SecureSession::HandshakeAsClient() {
    std::cout << "[Client] Starting Handshake..." << std::endl;
    
    // 1. Generate Keys
    if (!m_kex.GenerateScatteredKeys()) return false;
    ClientHello ch = m_kex.GenerateClientHello();

    // 2. Serialize ClientHello
    std::vector<uint8_t> ch_payload;
    ProtocolUtils::AppendVector(ch_payload, ch.pubkey_classic);
    ProtocolUtils::AppendVector(ch_payload, ch.pubkey_quantum);

    // 3. Send ClientHello
    if (!SendMessage(MsgType::CLIENT_HELLO, ch_payload)) return false;

    // 4. Receive ServerHello
    auto sh_payload_opt = ReceiveMessage(MsgType::SERVER_HELLO);
    if (!sh_payload_opt) return false;

    // 5. Provide to KEX (Need to deserialize)
    std::vector<uint8_t>& sh_data = sh_payload_opt.value();
    ServerHello sh;
    size_t offset = 0;
    
    try {
        sh.status = sh_data.at(offset++); // TODO: ProtocolUtils doesn't assume status byte if not serialized?
        // Wait, my previous walkthrough diagram showed Status. But let's check KEX logic.
        // Actually HybridKeyExchange::ProcessClientHello returns ServerHello struct.
        // Let's assume we stick to simple serialization: [Status(1)] [ClassicVec] [QuantumVec]
        
        // Actually I should look at how I will Serialize it on Server side.
        // Let's be robust.
        // Re-do serialization logic here to match Server:
        // ServerHello struct has: uint8 status, vec classic, vec quantum.
        // So offset 0 is status.
        
        // Let's implement serialization symmetric.
        // But Deserialize code:
        sh.pubkey_classic = ProtocolUtils::ReadVector(sh_data, offset);
        sh.ciphertext_quantum = ProtocolUtils::ReadVector(sh_data, offset);
    } catch (const std::exception& e) {
        std::cerr << "Deserialization error: " << e.what() << std::endl;
        return false;
    }

    // 6. Process
    if (!m_kex.ProcessServerHello(sh)) {
        std::cerr << "Key Exchange failed" << std::endl;
        return false;
    }

    m_session_key = m_kex.GetSessionKey();
    if (m_session_key.empty()) return false;

    std::cout << "[Client] Handshake Complete. Secure." << std::endl;
    return true;
}

bool SecureSession::HandshakeAsServer() {
    std::cout << "[Server] Waiting for ClientHello..." << std::endl;

    // 1. Receive ClientHello
    auto ch_payload_opt = ReceiveMessage(MsgType::CLIENT_HELLO);
    if (!ch_payload_opt) return false;

    // 2. Deserialize
    std::vector<uint8_t>& ch_data = ch_payload_opt.value();
    ClientHello ch;
    size_t offset = 0;
    try {
        ch.pubkey_classic = ProtocolUtils::ReadVector(ch_data, offset);
        ch.pubkey_quantum = ProtocolUtils::ReadVector(ch_data, offset);
    } catch (const std::exception& e) {
        std::cerr << "Deserialization error" << std::endl;
        return false;
    }

    // 3. Process
    auto sh_opt = m_kex.ProcessClientHello(ch);
    if (!sh_opt) {
        std::cerr << "Invalid ClientHello" << std::endl;
        // Should send error
        return false;
    }
    ServerHello sh = sh_opt.value();

    // 4. Serialize ServerHello
    // Format: [Status(1)? No, my ProtocolUtils::ReadVector on Client didn't read status byte first, it read vector directly?]
    // Ah, in Client Handshake I wrote: `sh.status = sh_data.at(offset++);` then `ReadVector`.
    // KEX defines ServerHello with `uint8_t status`.
    
    std::vector<uint8_t> sh_payload;
    sh_payload.push_back(sh.status); 
    ProtocolUtils::AppendVector(sh_payload, sh.pubkey_classic);
    ProtocolUtils::AppendVector(sh_payload, sh.ciphertext_quantum);

    // 5. Send
    if (!SendMessage(MsgType::SERVER_HELLO, sh_payload)) return false;

    m_session_key = m_kex.GetSessionKey();
    if (m_session_key.empty()) return false;

    std::cout << "[Server] Handshake Complete. Secure." << std::endl;
    return true;
}

std::vector<uint8_t> SecureSession::Encrypt(const std::vector<uint8_t>& plaintext) {
    if (m_session_key.empty()) return {};

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> iv(GCM_IV_SIZE);
    RAND_bytes(iv.data(), GCM_IV_SIZE);

    // Output: [IV] [Ciphertext] [Tag]
    std::vector<uint8_t> output;
    output.reserve(GCM_IV_SIZE + plaintext.size() + GCM_TAG_SIZE);
    output.insert(output.end(), iv.begin(), iv.end());

    int len;
    int ciphertext_len;
    std::vector<uint8_t> ciphertext(plaintext.size() + 16); // Block size padding potentially

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, m_session_key.data(), iv.data());

    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    // Tag
    std::vector<uint8_t> tag(GCM_TAG_SIZE);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag.data());

    output.insert(output.end(), ciphertext.begin(), ciphertext.end());
    output.insert(output.end(), tag.begin(), tag.end());

    EVP_CIPHER_CTX_free(ctx);
    return output;
}

std::optional<std::vector<uint8_t>> SecureSession::Decrypt(const std::vector<uint8_t>& input, 
                                            const std::vector<uint8_t>& iv, 
                                            const std::vector<uint8_t>& tag) {
    if (m_session_key.empty()) return std::nullopt;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> plaintext(input.size());
    int len;
    int plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, m_session_key.data(), iv.data());

    EVP_DecryptUpdate(ctx, plaintext.data(), &len, input.data(), input.size());
    plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, (void*)tag.data());

    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext.resize(plaintext_len);
        return plaintext;
    } else {
        std::cerr << "Decryption Auth Failed" << std::endl;
        return std::nullopt;
    }
}

bool SecureSession::SendEncrypted(const std::string& plaintext_str) {
    std::vector<uint8_t> plaintext(plaintext_str.begin(), plaintext_str.end());
    std::vector<uint8_t> encrypted_blob = Encrypt(plaintext);
    if (encrypted_blob.empty()) return false;
    
    return SendMessage(MsgType::SECURE_PAYLOAD, encrypted_blob);
}

std::optional<std::string> SecureSession::ReceiveEncrypted() {
    auto msg_opt = ReceiveMessage(MsgType::SECURE_PAYLOAD);
    if (!msg_opt) return std::nullopt;

    std::vector<uint8_t>& blob = msg_opt.value();
    // Blur: [IV 12] [Ciphertext N] [Tag 16]
    if (blob.size() < GCM_IV_SIZE + GCM_TAG_SIZE) return std::nullopt;

    std::vector<uint8_t> iv(blob.begin(), blob.begin() + GCM_IV_SIZE);
    std::vector<uint8_t> tag(blob.end() - GCM_TAG_SIZE, blob.end());
    std::vector<uint8_t> ciphertext(blob.begin() + GCM_IV_SIZE, blob.end() - GCM_TAG_SIZE);

    auto decrypted_opt = Decrypt(ciphertext, iv, tag);
    if (!decrypted_opt) return std::nullopt;

    std::vector<uint8_t>& plain = decrypted_opt.value();
    return std::string(plain.begin(), plain.end());
}

} // namespace quantum_shield
