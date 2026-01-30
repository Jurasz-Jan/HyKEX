FROM ubuntu:22.04

# Install build tools and dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Build liboqs from source
WORKDIR /opt
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    mkdir build && cd build && \
    cmake .. -DOQS_USE_OPENSSL=ON -DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX=/usr/local && \
    make -j2 && \
    make install && \
    ldconfig

# Set workdir
WORKDIR /app

# Copy source
COPY . .

# Build project
RUN ls -l /usr/local/lib && find /usr/local -name "liboqs*" && \
    cmake -B build -S . && \
    cmake --build build

CMD ["./build/quantum_shield"]
