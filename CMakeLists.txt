cmake_minimum_required(VERSION 3.15)
project(QuantumShield LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


find_package(OpenSSL REQUIRED)

# Direct dynamic discovery of liboqs
find_library(LIBOQS_LIB_FINAL NAMES liboqs.a oqs liboqs PATHS /usr/local/lib NO_DEFAULT_PATH)
find_path(LIBOQS_INC_FINAL NAMES oqs/kem.h PATHS /usr/local/include NO_DEFAULT_PATH)

# Explicit fallback check
if(NOT LIBOQS_LIB_FINAL)
    if(EXISTS "/usr/local/lib/liboqs.a")
        set(LIBOQS_LIB_FINAL "/usr/local/lib/liboqs.a")
        message(STATUS "Force set LIBOQS_LIB_FINAL to /usr/local/lib/liboqs.a")
    endif()
endif()

if(LIBOQS_LIB_FINAL AND LIBOQS_INC_FINAL)
    message(STATUS "Using liboqs: ${LIBOQS_LIB_FINAL}")
    add_library(liboqs::liboqs UNKNOWN IMPORTED)
    set_target_properties(liboqs::liboqs PROPERTIES
        IMPORTED_LOCATION "${LIBOQS_LIB_FINAL}"
        INTERFACE_INCLUDE_DIRECTORIES "${LIBOQS_INC_FINAL}"
    )
else()
     message(FATAL_ERROR "Could not find liboqs! Checked /usr/local/lib/liboqs.a")
endif()



add_executable(quantum_shield 
    main.cpp
    HybridKeyExchange.cpp
    TcpServer.cpp
    TcpClient.cpp
    SecureSession.cpp
    Benchmark.cpp
)
target_link_libraries(quantum_shield PRIVATE liboqs::liboqs OpenSSL::SSL OpenSSL::Crypto m)

# Testing
enable_testing()
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(unit_tests 
    tests/test_hybrid_kx.cpp
    tests/test_network.cpp
    tests/test_secure_session.cpp
    HybridKeyExchange.cpp
    TcpServer.cpp
    TcpClient.cpp
    SecureSession.cpp
)
target_link_libraries(unit_tests PRIVATE GTest::gtest_main liboqs::liboqs OpenSSL::SSL OpenSSL::Crypto m)
add_test(NAME HybridKeyExchangeTest COMMAND unit_tests)
