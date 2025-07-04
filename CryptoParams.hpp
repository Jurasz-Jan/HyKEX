#pragma once

#include <cstdint>
#include <string>

namespace quantum_shield {

// Constants for algorithms
constexpr const char* OQS_ALG_NAME = "ML-KEM-768";
constexpr size_t X25519_PUBKEY_SIZE = 32;
constexpr size_t X25519_PRIVKEY_SIZE = 32;
constexpr size_t X25519_SHARED_SECRET_SIZE = 32;

// ML-KEM-768 (Kyber-768) Constants
// Defined in liboqs headers, but good to have local references or asserts
// Public Key: 1184 bytes
// Secret Key: 2400 bytes
// Ciphertext: 1088 bytes
// Shared Secret: 32 bytes

constexpr size_t KYBER_768_PUBKEY_SIZE = 1184;
constexpr size_t KYBER_768_PRIVKEY_SIZE = 2400;
constexpr size_t KYBER_768_CIPHERTEXT_SIZE = 1088;
constexpr size_t KYBER_768_SHARED_SECRET_SIZE = 32;

// Protocol Constants
constexpr size_t HKDF_SALT_SIZE = 32; // SHA-256 output size
constexpr size_t SESSION_KEY_SIZE = 32; // AES-256

} // namespace quantum_shield
