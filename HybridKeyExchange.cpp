#include "HybridKeyExchange.hpp"
#include <iostream>
#include <stdexcept>
#include <cstring>

// Liboqs
#include <oqs/kem.h>

// OpenSSL
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

namespace quantum_shield {

HybridKeyExchange::HybridKeyExchange() {
    // Ensure OQS is initialized (it's safe to call multiple times or we can manage globally)
    // Ideally main() calls OQS_init(), but safety check here is good.
    // OQS_init(); // Leaving to main/global context for now to avoid redundant init/destroy
}

HybridKeyExchange::~HybridKeyExchange() {
    // Securely clear memory if possible (std::vector doesn't do this automatically without custom allocator)
    // For prototype, we rely on OS cleanup, but in prod we'd use sodium_memzero or strictly wiped memory.
    std::fill(m_classic_priv_key.begin(), m_classic_priv_key.end(), 0);
    std::fill(m_quantum_priv_key.begin(), m_quantum_priv_key.end(), 0);
    std::fill(m_session_key.begin(), m_session_key.end(), 0);
}

bool HybridKeyExchange::GenerateScatteredKeys() {
    // 1. Generate Quantum Keys (ML-KEM-768)
    OQS_KEM* kem = OQS_KEM_new(OQS_ALG_NAME);
    if (kem == nullptr) {
        std::cerr << "Failed to create OQS KEM context for " << OQS_ALG_NAME << std::endl;
        return false;
    }

    m_quantum_pub_key.resize(kem->length_public_key);
    m_quantum_priv_key.resize(kem->length_secret_key);

    if (OQS_KEM_keypair(kem, m_quantum_pub_key.data(), m_quantum_priv_key.data()) != OQS_SUCCESS) {
        std::cerr << "OQS Keypair generation failed" << std::endl;
        OQS_KEM_free(kem);
        return false;
    }
    OQS_KEM_free(kem);

    // 2. Generate Classic Keys (X25519)
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) return false;

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    
    // Extract raw public key
    size_t pub_len = X25519_PUBKEY_SIZE;
    m_classic_pub_key.resize(pub_len);
    if (EVP_PKEY_get_raw_public_key(pkey, m_classic_pub_key.data(), &pub_len) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return false;
    }

    // Extract raw private key
    size_t priv_len = X25519_PRIVKEY_SIZE;
    m_classic_priv_key.resize(priv_len);
    if (EVP_PKEY_get_raw_private_key(pkey, m_classic_priv_key.data(), &priv_len) <= 0) {
         EVP_PKEY_free(pkey);
         EVP_PKEY_CTX_free(pctx);
         return false;
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);

    m_keys_generated = true;
    return true;
}

std::vector<uint8_t> HybridKeyExchange::GetClassicPublicKey() const {
    return m_classic_pub_key;
}

std::vector<uint8_t> HybridKeyExchange::GetQuantumPublicKey() const {
    return m_quantum_pub_key;
}

ClientHello HybridKeyExchange::GenerateClientHello() {
    if (!m_keys_generated) {
        GenerateScatteredKeys();
    }
    
    ClientHello hello;
    hello.protocol_version = 0x01;
    hello.cipher_suite = 0x01; // X25519_MLKEM768
    hello.pubkey_classic = m_classic_pub_key;
    hello.pubkey_quantum = m_quantum_pub_key;
    return hello;
}

std::optional<ServerHello> HybridKeyExchange::ProcessClientHello(const ClientHello& client_hello) {
    // Server logic:
    // 1. Generate own Classic Keypair (Ephemeral)
    if (!GenerateScatteredKeys()) {
        std::cerr << "Server key generation failed" << std::endl;
        return std::nullopt;
    }

    // 2. Compute Classic Shared Secret (Server Priv + Client Pub)
    std::vector<uint8_t> classic_shared_secret = ComputeClassicSharedSecret(client_hello.pubkey_classic);
    if (classic_shared_secret.empty()) {
        std::cerr << "Classic ECDH failed" << std::endl;
        return std::nullopt;
    }

    // 3. Encapsulate Quantum Secret (Client Quantum Pub)
    OQS_KEM* kem = OQS_KEM_new(OQS_ALG_NAME);
    if (!kem) return std::nullopt;

    std::vector<uint8_t> ciphertext(kem->length_ciphertext);
    std::vector<uint8_t> quantum_shared_secret(kem->length_shared_secret);

    // Validate lengths
    if (client_hello.pubkey_quantum.size() != kem->length_public_key) {
        std::cerr << "Invalid Client Quantum Public Key size" << std::endl;
        OQS_KEM_free(kem);
        return std::nullopt;
    }

    if (OQS_KEM_encaps(kem, ciphertext.data(), quantum_shared_secret.data(), client_hello.pubkey_quantum.data()) != OQS_SUCCESS) {
        std::cerr << "Kyber encapsulation failed" << std::endl;
        OQS_KEM_free(kem);
        return std::nullopt;
    }
    OQS_KEM_free(kem);

    // 4. Derive Session Key (HKDF)
    m_session_key = DeriveKey(classic_shared_secret, quantum_shared_secret);
    if (m_session_key.empty()) {
        return std::nullopt;
    }
    m_handshake_complete = true;

    // 5. Construct ServerHello
    ServerHello s_hello;
    s_hello.status = 0x00;
    s_hello.pubkey_classic = m_classic_pub_key;
    s_hello.ciphertext_quantum = ciphertext;
    s_hello.auth_tag.resize(16, 0); // Placeholder for auth tag (implemented later in secure layer)

    return s_hello;
}

bool HybridKeyExchange::ProcessServerHello(const ServerHello& server_hello) {
    if (!m_keys_generated) {
        std::cerr << "Client keys not generated before processing ServerHello" << std::endl;
        return false;
    }

    if (server_hello.status != 0x00) {
        std::cerr << "Server reported error" << std::endl;
        return false;
    }

    // 1. Compute Classic Shared Secret (Client Priv + Server Pub)
    std::vector<uint8_t> classic_shared_secret = ComputeClassicSharedSecret(server_hello.pubkey_classic);
    if (classic_shared_secret.empty()) {
         std::cerr << "Client classic ECDH failed" << std::endl;
         return false;
    }

    // 2. Decapsulate Quantum Secret (Client Quantum Priv + Server Ciphertext)
    OQS_KEM* kem = OQS_KEM_new(OQS_ALG_NAME);
    if (!kem) return false;

    std::vector<uint8_t> quantum_shared_secret(kem->length_shared_secret);
    
    // Validate length
    if (server_hello.ciphertext_quantum.size() != kem->length_ciphertext) {
        std::cerr << "Invalid Server Ciphertext length" << std::endl;
        OQS_KEM_free(kem);
        return false;
    }

    if (OQS_KEM_decaps(kem, quantum_shared_secret.data(), server_hello.ciphertext_quantum.data(), m_quantum_priv_key.data()) != OQS_SUCCESS) {
        std::cerr << "Kyber decapsulation failed" << std::endl;
        OQS_KEM_free(kem);
        return false;
    }
    OQS_KEM_free(kem);

    // 3. Derive Session Key
    m_session_key = DeriveKey(classic_shared_secret, quantum_shared_secret);
    
    if (!m_session_key.empty()) {
        m_handshake_complete = true;
        return true;
    }
    return false;
}

std::vector<uint8_t> HybridKeyExchange::GetSessionKey() const {
    if (!m_handshake_complete) return {};
    return m_session_key;
}

std::vector<uint8_t> HybridKeyExchange::ComputeClassicSharedSecret(const std::vector<uint8_t>& peer_pub_key) {
    if (peer_pub_key.size() != X25519_PUBKEY_SIZE) {
        return {};
    }

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx) return {};

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    // Create EVP_PKEY for our private key
    EVP_PKEY* my_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, m_classic_priv_key.data(), m_classic_priv_key.size());
    if (!my_key) {
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    // Create EVP_PKEY for peer public key
    EVP_PKEY* peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub_key.data(), peer_pub_key.size());
    if (!peer_key) {
        EVP_PKEY_free(my_key);
        EVP_PKEY_CTX_free(pctx);
        return {};
    }

    if (EVP_PKEY_derive_set_peer(pctx, peer_key) <= 0) {
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(my_key);
        EVP_PKEY_CTX_free(pctx);
        return {};
    }
    
    // We strictly need to set the context's pkey (our private key) too? 
    // Usually EVP_PKEY_derive_init takes pctx created from a PKEY.
    // Let's create pctx from my_key instead.
    
    EVP_PKEY_CTX_free(pctx);
    pctx = EVP_PKEY_CTX_new(my_key, NULL);
    if (!pctx) {
         EVP_PKEY_free(peer_key);
         EVP_PKEY_free(my_key);
         return {};
    }
    if (EVP_PKEY_derive_init(pctx) <= 0) {
         EVP_PKEY_free(peer_key);
         EVP_PKEY_free(my_key);
         EVP_PKEY_CTX_free(pctx);
         return {};
    }
    if (EVP_PKEY_derive_set_peer(pctx, peer_key) <= 0) {
         EVP_PKEY_free(peer_key);
         EVP_PKEY_free(my_key);
         EVP_PKEY_CTX_free(pctx);
         return {};  
    }

    size_t secret_len;
    if (EVP_PKEY_derive(pctx, NULL, &secret_len) <= 0) {
         EVP_PKEY_free(peer_key);
         EVP_PKEY_free(my_key);
         EVP_PKEY_CTX_free(pctx);
         return {}; 
    }

    std::vector<uint8_t> secret(secret_len);
    if (EVP_PKEY_derive(pctx, secret.data(), &secret_len) <= 0) {
         EVP_PKEY_free(peer_key);
         EVP_PKEY_free(my_key);
         EVP_PKEY_CTX_free(pctx);
         return {}; 
    }
    
    EVP_PKEY_free(peer_key);
    EVP_PKEY_free(my_key);
    EVP_PKEY_CTX_free(pctx);
    
    return secret;
}

std::vector<uint8_t> HybridKeyExchange::DeriveKey(const std::vector<uint8_t>& classic_secret, 
                                                  const std::vector<uint8_t>& quantum_secret) {
    // HKDF-SHA256
    // IKM = classic_secret || quantum_secret
    // Salt = (optional, can be headers or random, for now empty or fixed)
    
    std::vector<uint8_t> ikm;
    ikm.reserve(classic_secret.size() + quantum_secret.size());
    ikm.insert(ikm.end(), classic_secret.begin(), classic_secret.end());
    ikm.insert(ikm.end(), quantum_secret.begin(), quantum_secret.end());
    
    std::vector<uint8_t> output_key(SESSION_KEY_SIZE);
    
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);

    OSSL_PARAM params[5];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char*)"SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm.data(), ikm.size());
    // Salt: For now using empty/NULL salt as per simplified spec. 
    // Ideally we should exchange a random salt in Hello messages.
    // Spec says: Session_Key = HKDF(Salt, IKM)
    // If salt is not exchanged, we assume fixed or empty. Let's use empty string for now or "QuantumShield"
    char salt[] = "QuantumShield";
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, strlen(salt));
    char info[] = "HybridKeyExchange";
    params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, strlen(info));
    params[4] = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, output_key.data(), SESSION_KEY_SIZE, params) <= 0) {
        std::cerr << "HKDF derivation failed" << std::endl;
        EVP_KDF_CTX_free(kctx);
        return {};
    }
    EVP_KDF_CTX_free(kctx);

    return output_key;
}

} // namespace quantum_shield
