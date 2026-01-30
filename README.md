# Quantum-Shield 6G

**Quantum-Resistant Hybrid Communication System**

## Overview
Quantum-Shield 6G is a C++20 prototype designed to secure communications against future quantum "Harvest Now, Decrypt Later" threats. It implements a **Hybrid Key Exchange** mechanism, combining  **X25519** (Elliptic Curve) with **ML-KEM-768**. 

The system negotiates a shared secret over a standard TCP connection and establishes an authenticated encrypted channel using **AES-256-GCM**. It is built for performance, security, and simplicity, utilizing a custom binary wire protocol.

## Quick Start

### Prerequisites
*   **Docker Engine** (Recommended)
*   *Alternatively*: CMake 3.15+, C++20 Compiler, OpenSSL 3.0, liboqs

### Installation (Docker)
Build the container image:
```bash
docker build -t quantum-shield .
```

## Usage

The application supports three modes: Server, Client, and Benchmark.

### Server
Listens for incoming connections on a specified port.
```bash
docker run --rm -p 9999:9999 quantum-shield ./quantum_shield --server 9999
```

### Client
Connects to the server, performs the Hybrid Handshake, and exchanges an encrypted message.
```bash
# Note: Use --network host or the container IP if running separate containers
docker run --rm --network host quantum-shield ./quantum_shield --client 127.0.0.1 9999
```

### Performance Benchmark
Measures the latency of Key Generation, Encapsulation, and Decapsulation.
```bash
docker run --rm quantum-shield ./quantum_shield --benchmark 1000
```
*Outputs detailed CSV results to `benchmark_results.csv`.*

## Technical Details
For a deep dive into the architecture, cryptographic parameters, and protocol specification, please refer to the [Technical Documentation](TECHNICAL_DOCUMENTATION.md).

---
*Developed for the Next-Gen Network Security Initiative.*
