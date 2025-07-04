#pragma once

#include "CryptoParams.hpp"
#include <vector>
#include <memory>
#include <span>
#include <optional>

// Forward declarations to avoid exposing implementation details (PIMPL or just strict headers)
// But for this project, we might just include library headers in .cpp to keep .hpp clean.

namespace quantum_shield {

// Structure definitions matching the specification
struct ClientHello {
    uint8_t protocol_version;
    uint8_t cipher_suite;
    std::vector<uint8_t> pubkey_classic; // Size: 32
    std::vector<uint8_t> pubkey_quantum; // Size: 1184
};

struct ServerHello {
    uint8_t status;
    std::vector<uint8_t> pubkey_classic; // Size: 32
    std::vector<uint8_t> ciphertext_quantum; // Size: 1088
    std::vector<uint8_t> auth_tag;       // Size: 16 (Not used in pure KX, but in handshake)
};

class HybridKeyExchange {
public:
    HybridKeyExchange();
    ~HybridKeyExchange();

    // Prevent copying to avoid accidental key duplication
    HybridKeyExchange(const HybridKeyExchange&) = delete;
    HybridKeyExchange& operator=(const HybridKeyExchange&) = delete;

    HybridKeyExchange(HybridKeyExchange&&) = default;
    HybridKeyExchange& operator=(HybridKeyExchange&&) = default;

    // Phase 1: Key Generation (Executed by both Client and Server, though Server mainly uses Ephemeral in this specific flow?)
    // In this specific protocol:
    // - Client generates both (X25519 + Kyber) keypairs.
    // - Server generates X25519 keypair and Encapsulates for Kyber.
    // Let's make it flexible.
    bool GenerateScatteredKeys(); // Generates local Classic and Quantum Keypairs

    // Getters for Public Keys (to avoid exposing private keys)
    std::vector<uint8_t> GetClassicPublicKey() const;
    std::vector<uint8_t> GetQuantumPublicKey() const;

    // Full Client Hello construction
    ClientHello GenerateClientHello();

    // Server-side processing:
    // 1. Accepts ClientHello
    // 2. Generates its own X25519 keypair
    // 3. Encapsulates Kyber (uses Client's Quantum PubKey)
    // 4. Derives Session Key
    // 5. Returns keys/ciphertext for ServerHello
    // Returns: Optional ServerHello params (QuantumCT + ClassicPub) on success
    std::optional<ServerHello> ProcessClientHello(const ClientHello& client_hello);

    // Client-side processing of Server response:
    // 1. Accepts ServerHello (Classic PubKey + Quantum CT)
    // 2. Decapsulates Kyber (uses own Quantum PrivKey)
    // 3. Computes Classic Shared Secret (Client Priv + Server Pub)
    // 4. Derives Session Key
    bool ProcessServerHello(const ServerHello& server_hello);

    // Get the final session key (only available after handshake)
    std::vector<uint8_t> GetSessionKey() const;

private:
    // Internal state
    std::vector<uint8_t> m_classic_priv_key;
    std::vector<uint8_t> m_classic_pub_key;
    
    std::vector<uint8_t> m_quantum_priv_key;
    std::vector<uint8_t> m_quantum_pub_key;

    std::vector<uint8_t> m_session_key;

    bool m_keys_generated = false;
    bool m_handshake_complete = false;

    // Helper: Classic ECDH (X25519)
    // Returns shared secret
    std::vector<uint8_t> ComputeClassicSharedSecret(const std::vector<uint8_t>& peer_pub_key);

    // Helper: HKDF
    std::vector<uint8_t> DeriveKey(const std::vector<uint8_t>& classic_secret, 
                                   const std::vector<uint8_t>& quantum_secret);
};

} // namespace quantum_shield
