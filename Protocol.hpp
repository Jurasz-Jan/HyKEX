#pragma once

#include <cstdint>
#include <vector>
#include <arpa/inet.h> // For htonl/ntohl on Linux (and Windows with Winsock)
#include <cstring>
#include <stdexcept>

// For Windows/Linux compatibility regarding byte order
#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif

namespace quantum_shield {

// Message Types
enum class MsgType : uint8_t {
    CLIENT_HELLO = 0x01,
    SERVER_HELLO = 0x02,
    SECURE_PAYLOAD = 0x03,
    ERROR = 0xFF
};

// Protocol Header
// [1 byte Type] [4 bytes Length (Network Byte Order)]
constexpr size_t HEADER_SIZE = 5;

struct ProtocolHeader {
    MsgType type;
    uint32_t length; // Length of the payload
};

class ProtocolUtils {
public:
    static std::vector<uint8_t> SerializeHeader(MsgType type, uint32_t payload_length) {
        std::vector<uint8_t> buffer(HEADER_SIZE);
        buffer[0] = static_cast<uint8_t>(type);
        
        uint32_t net_len = htonl(payload_length);
        std::memcpy(&buffer[1], &net_len, 4);
        
        return buffer;
    }

    static ProtocolHeader DeserializeHeader(const std::vector<uint8_t>& buffer) {
        if (buffer.size() < HEADER_SIZE) {
            throw std::runtime_error("Buffer too small for header");
        }

        ProtocolHeader header;
        header.type = static_cast<MsgType>(buffer[0]);
        
        uint32_t net_len;
        std::memcpy(&net_len, &buffer[1], 4);
        header.length = ntohl(net_len);
        
        return header;
    }
    
    // Helper to serialize vector size (4 bytes) + vector data
    static void AppendVector(std::vector<uint8_t>& buffer, const std::vector<uint8_t>& data) {
        uint32_t len = htonl(static_cast<uint32_t>(data.size()));
        size_t current_size = buffer.size();
        buffer.resize(current_size + 4 + data.size());
        
        std::memcpy(&buffer[current_size], &len, 4);
        std::memcpy(&buffer[current_size + 4], data.data(), data.size());
    }

    // Helper to read vector from offset
    static std::vector<uint8_t> ReadVector(const std::vector<uint8_t>& buffer, size_t& offset) {
        if (offset + 4 > buffer.size()) throw std::runtime_error("Buffer underflow reading vector length");
        
        uint32_t net_len;
        std::memcpy(&net_len, &buffer[offset], 4);
        uint32_t len = ntohl(net_len);
        offset += 4;

        if (offset + len > buffer.size()) throw std::runtime_error("Buffer underflow reading vector data");
        
        std::vector<uint8_t> data(buffer.begin() + offset, buffer.begin() + offset + len);
        offset += len;
        return data;
    }
};

} // namespace quantum_shield
